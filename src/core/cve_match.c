#include "crimp/cve.h"

#include "yaml_util.h"

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <yaml.h>

/* Version comparison (issue #12). Splits on '.'/'-' into segments, each an
 * optional numeric run followed by an optional lowercase-letter suffix
 * (e.g. "1.1.1n" -> segments (1,""), (1,""), (1,"n")) - numeric part
 * orders first, suffix breaks ties (empty suffix sorts before any letter,
 * so "1.1.1" < "1.1.1a" - the base release predates its own first lettered
 * patch). A version with fewer segments than the other is compared as if
 * padded with (0,"") segments, so "1.1" < "1.1.1" as expected. */
typedef struct {
    unsigned long long num;
    char suffix[8];
} version_segment;

static const char *parse_segment(const char *p, version_segment *seg) {
    seg->num = 0;
    /* `version` ultimately traces back to crimp_identify_components()
     * scanning raw (untrusted) firmware file content - a digit run of
     * 19+ characters would overflow `unsigned long long` (max ~1.8e19,
     * 20 digits) and silently wrap to an arbitrary small value, which
     * could make version_compare() misjudge older-vs-newer. Cap
     * accumulation at 18 digits (always safely representable) and
     * saturate rather than wrap past that - an implausibly long digit
     * run then just sorts as "very new", not as an unpredictable wrapped
     * value. */
    int digits = 0;
    while (isdigit((unsigned char)*p)) {
        if (digits < 18) {
            seg->num = seg->num * 10 + (unsigned long long)(*p - '0');
            digits++;
        } else {
            seg->num = ULLONG_MAX;
        }
        p++;
    }
    size_t i = 0;
    while (isalpha((unsigned char)*p) && i < sizeof(seg->suffix) - 1) {
        char c = *p;
        if (c >= 'A' && c <= 'Z') {
            c = (char)(c - 'A' + 'a');
        }
        seg->suffix[i++] = c;
        p++;
    }
    seg->suffix[i] = '\0';
    while (*p && *p != '.' && *p != '-') {
        p++; /* skip any other junk in this segment rather than misparse it as a new one */
    }
    return p;
}

static int version_compare(const char *a, const char *b) {
    while (*a || *b) {
        version_segment sa = {0, {0}};
        version_segment sb = {0, {0}};
        if (*a) {
            a = parse_segment(a, &sa);
        }
        if (*b) {
            b = parse_segment(b, &sb);
        }
        if (sa.num != sb.num) {
            return sa.num < sb.num ? -1 : 1;
        }
        int c = strcmp(sa.suffix, sb.suffix);
        if (c != 0) {
            return c < 0 ? -1 : 1;
        }
        if (*a == '.' || *a == '-') {
            a++;
        }
        if (*b == '.' || *b == '-') {
            b++;
        }
    }
    return 0;
}

typedef enum { OP_LT, OP_LE, OP_GT, OP_GE, OP_EQ } range_op;

/* Evaluates one comma-separated `affected` condition list (see cve.h)
 * against `version` - every condition must hold (AND). A malformed
 * condition (bad operator, empty version token) makes the whole list
 * fail-closed (not affected) rather than risk misreading intent either
 * way. */
static int version_satisfies(const char *version, const char *affected) {
    if (affected[0] == '\0') {
        /* Zero conditions would otherwise vacuously satisfy the loop below
         * (AND over an empty set is true) and match every version of the
         * component - the same "empty pattern matches everything" trap
         * yaml_rules.c already guards against for its own `pattern` field
         * (src/core/yaml_rules.c). An empty `affected` is malformed, not a
         * real "no constraint" - fail closed. */
        return 0;
    }
    const char *p = affected;
    while (*p != '\0') {
        while (*p == ' ') {
            p++;
        }
        range_op op;
        if (p[0] == '<' && p[1] == '=') {
            op = OP_LE;
            p += 2;
        } else if (p[0] == '>' && p[1] == '=') {
            op = OP_GE;
            p += 2;
        } else if (p[0] == '=' && p[1] == '=') {
            op = OP_EQ;
            p += 2;
        } else if (p[0] == '<') {
            op = OP_LT;
            p += 1;
        } else if (p[0] == '>') {
            op = OP_GT;
            p += 1;
        } else {
            return 0;
        }

        char verbuf[64];
        size_t i = 0;
        while (*p != '\0' && *p != ',' && i < sizeof(verbuf) - 1) {
            verbuf[i++] = *p++;
        }
        /* Reject rather than silently compare against a truncated version
         * token - if we stopped because the buffer filled up (not because
         * we reached a real delimiter), what's in verbuf is not the whole
         * token. No real version in this dataset is anywhere near 63
         * characters; this only ever fires on a malformed/hand-edited
         * `affected` field. */
        if (i == 0 || (*p != '\0' && *p != ',')) {
            return 0;
        }
        verbuf[i] = '\0';

        int cmp = version_compare(version, verbuf);
        int ok;
        switch (op) {
            case OP_LT:
                ok = cmp < 0;
                break;
            case OP_LE:
                ok = cmp <= 0;
                break;
            case OP_GT:
                ok = cmp > 0;
                break;
            case OP_GE:
                ok = cmp >= 0;
                break;
            default:
                ok = cmp == 0;
                break;
        }
        if (!ok) {
            return 0;
        }
        if (*p == ',') {
            p++;
        }
    }
    return 1;
}

/* One CVE entry under a dataset component - id/affected/severity/
 * description are all required scalar fields; a missing one skips just
 * that entry (best-effort, matching crimp_yaml_rules_load_dir's per-file
 * posture) rather than rejecting the whole dataset over one bad record.
 * Parsed once per dataset CVE entry (not once per matching runtime
 * component instance - see match_component_entry) and checked against
 * every instance in `components` sharing `dataset_component_name`. */
static void match_cve_entry(yaml_document_t *doc, yaml_node_t *cve_entry,
                             const crimp_component_list *components,
                             const char *dataset_component_name, crimp_finding_list *out) {
    if (!cve_entry || cve_entry->type != YAML_MAPPING_NODE) {
        return;
    }
    char *id = crimp_yaml_dup_scalar(crimp_yaml_mapping_get(doc, cve_entry, "id"));
    char *affected = crimp_yaml_dup_scalar(crimp_yaml_mapping_get(doc, cve_entry, "affected"));
    char *severity_str =
        crimp_yaml_dup_scalar(crimp_yaml_mapping_get(doc, cve_entry, "severity"));
    char *description =
        crimp_yaml_dup_scalar(crimp_yaml_mapping_get(doc, cve_entry, "description"));

    if (id && affected && affected[0] != '\0' && severity_str && description) {
        /* An unrecognized severity string (a hand-edited or future dataset
         * entry, or a real NVD "NONE" rating that slipped past the sync
         * script) falls back to LOW rather than silently dropping an
         * otherwise-genuine match - a missing finding with no diagnostic
         * trail is a worse failure mode for a security scanner than one
         * reported at a possibly-imprecise severity. */
        crimp_yaml_str_to_lower(severity_str);
        crimp_severity severity;
        if (crimp_yaml_parse_severity(severity_str, &severity) != 0) {
            severity = CRIMP_SEVERITY_LOW;
        }

        for (size_t i = 0; i < components->count; i++) {
            const crimp_component *comp = &components->items[i];
            if (comp->version[0] == '\0' || strcmp(comp->component, dataset_component_name) != 0) {
                continue; /* unknown version can't safely be judged affected or not */
            }
            if (version_satisfies(comp->version, affected)) {
                char desc[1024];
                snprintf(desc, sizeof(desc), "%s (%s %s, %s)", description, comp->component,
                          comp->version, comp->path);
                crimp_finding_list_add(out, id, desc, severity);
            }
        }
    }

    free(id);
    free(affected);
    free(severity_str);
    free(description);
}

static void match_component_entry(yaml_document_t *doc, yaml_node_t *dataset_component,
                                   const crimp_component_list *components,
                                   crimp_finding_list *out) {
    if (!dataset_component || dataset_component->type != YAML_MAPPING_NODE) {
        return;
    }
    yaml_node_t *name_node = crimp_yaml_mapping_get(doc, dataset_component, "name");
    yaml_node_t *cves_node = crimp_yaml_mapping_get(doc, dataset_component, "cves");
    char *name = crimp_yaml_dup_scalar(name_node);
    if (!name || !cves_node || cves_node->type != YAML_SEQUENCE_NODE) {
        free(name);
        return;
    }

    /* One pass over this component's CVE list, each entry parsed exactly
     * once - not once per matching runtime component instance. With
     * data/cve_dataset.yaml (thousands of entries for a widely-used
     * component like OpenSSL) and a firmware image that embeds the same
     * component in several statically-linked binaries, the original
     * per-instance-outer loop scaled matching cost as O(instances x CVEs)
     * instead of O(instances + CVEs). */
    for (yaml_node_item_t *item = cves_node->data.sequence.items.start;
         item < cves_node->data.sequence.items.top; item++) {
        yaml_node_t *cve_entry = yaml_document_get_node(doc, *item);
        match_cve_entry(doc, cve_entry, components, name, out);
    }
    free(name);
}

int crimp_cve_match_components(const char *dataset_path, const crimp_component_list *components,
                                crimp_finding_list *out) {
    FILE *f = fopen(dataset_path, "rb");
    if (!f) {
        return -1;
    }

    yaml_parser_t parser;
    if (!yaml_parser_initialize(&parser)) {
        fclose(f);
        return -1;
    }
    yaml_parser_set_input_file(&parser, f);

    yaml_document_t doc;
    int loaded = yaml_parser_load(&parser, &doc);
    yaml_parser_delete(&parser);
    fclose(f);
    if (!loaded) {
        return -1;
    }

    yaml_node_t *root = yaml_document_get_root_node(&doc);
    yaml_node_t *components_node = crimp_yaml_mapping_get(&doc, root, "components");
    if (!components_node || components_node->type != YAML_SEQUENCE_NODE) {
        yaml_document_delete(&doc);
        return -1;
    }

    for (yaml_node_item_t *item = components_node->data.sequence.items.start;
         item < components_node->data.sequence.items.top; item++) {
        yaml_node_t *entry = yaml_document_get_node(&doc, *item);
        match_component_entry(&doc, entry, components, out);
    }

    yaml_document_delete(&doc);
    return 0;
}
