#include "crimp/cve.h"

#include "yaml_util.h"

#include <ctype.h>
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
    while (isdigit((unsigned char)*p)) {
        seg->num = seg->num * 10 + (unsigned long long)(*p - '0');
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
        verbuf[i] = '\0';
        if (i == 0) {
            return 0;
        }

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
 * posture) rather than rejecting the whole dataset over one bad record. */
static void match_cve_entry(yaml_document_t *doc, yaml_node_t *cve_entry, const char *version,
                             const char *component_name, const char *path,
                             crimp_finding_list *out) {
    if (!cve_entry || cve_entry->type != YAML_MAPPING_NODE) {
        return;
    }
    char *id = crimp_yaml_dup_scalar(crimp_yaml_mapping_get(doc, cve_entry, "id"));
    char *affected = crimp_yaml_dup_scalar(crimp_yaml_mapping_get(doc, cve_entry, "affected"));
    char *severity_str =
        crimp_yaml_dup_scalar(crimp_yaml_mapping_get(doc, cve_entry, "severity"));
    char *description =
        crimp_yaml_dup_scalar(crimp_yaml_mapping_get(doc, cve_entry, "description"));

    if (id && affected && severity_str && description && version_satisfies(version, affected)) {
        for (char *c = severity_str; *c; c++) {
            if (*c >= 'A' && *c <= 'Z') {
                *c = (char)(*c - 'A' + 'a');
            }
        }
        crimp_severity severity;
        int have_severity = 1;
        if (strcmp(severity_str, "low") == 0) {
            severity = CRIMP_SEVERITY_LOW;
        } else if (strcmp(severity_str, "medium") == 0) {
            severity = CRIMP_SEVERITY_MEDIUM;
        } else if (strcmp(severity_str, "high") == 0) {
            severity = CRIMP_SEVERITY_HIGH;
        } else if (strcmp(severity_str, "critical") == 0) {
            severity = CRIMP_SEVERITY_CRITICAL;
        } else {
            severity = CRIMP_SEVERITY_LOW;
            have_severity = 0;
        }
        if (have_severity) {
            char desc[1024];
            snprintf(desc, sizeof(desc), "%s (%s %s, %s)", description, component_name, version,
                      path);
            crimp_finding_list_add(out, id, desc, severity);
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

    for (size_t i = 0; i < components->count; i++) {
        const crimp_component *comp = &components->items[i];
        if (comp->version[0] == '\0' || strcmp(comp->component, name) != 0) {
            continue; /* unknown version can't safely be judged affected or not */
        }
        for (yaml_node_item_t *item = cves_node->data.sequence.items.start;
             item < cves_node->data.sequence.items.top; item++) {
            yaml_node_t *cve_entry = yaml_document_get_node(doc, *item);
            match_cve_entry(doc, cve_entry, comp->version, comp->component, comp->path, out);
        }
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
