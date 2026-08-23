#include "crimp/yaml_rules.h"

#include "pattern_scan.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yaml.h>

void crimp_yaml_rule_list_init(crimp_yaml_rule_list *list) {
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static void rule_free(crimp_yaml_rule *r) {
    free(r->id);
    free(r->pattern);
    free(r->description);
}

void crimp_yaml_rule_list_free(crimp_yaml_rule_list *list) {
    for (size_t i = 0; i < list->count; i++) {
        rule_free(&list->items[i]);
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static int rule_list_add(crimp_yaml_rule_list *list, char *id, char *pattern, char *description,
                          crimp_severity severity) {
    if (list->count == list->capacity) {
        size_t new_capacity = list->capacity == 0 ? 8 : list->capacity * 2;
        crimp_yaml_rule *items =
            (crimp_yaml_rule *)realloc(list->items, new_capacity * sizeof(crimp_yaml_rule));
        if (!items) {
            return -1;
        }
        list->items = items;
        list->capacity = new_capacity;
    }
    crimp_yaml_rule *r = &list->items[list->count];
    r->id = id;
    r->pattern = pattern;
    r->description = description;
    r->severity = severity;
    list->count++;
    return 0;
}

/* Copies a scalar node's value into a fresh NUL-terminated heap string.
 * libyaml's scalar values aren't guaranteed NUL-terminated by the API
 * contract - always go through `.length`, never assume it. Returns NULL
 * for a non-scalar node or on allocation failure. */
static char *dup_scalar(const yaml_node_t *node) {
    if (!node || node->type != YAML_SCALAR_NODE) {
        return NULL;
    }
    char *s = (char *)malloc(node->data.scalar.length + 1);
    if (!s) {
        return NULL;
    }
    memcpy(s, node->data.scalar.value, node->data.scalar.length);
    s[node->data.scalar.length] = '\0';
    return s;
}

/* Finds `key` among a YAML_MAPPING_NODE's pairs and returns its value node,
 * or NULL if `map_node` isn't a mapping or has no such key. */
static yaml_node_t *mapping_get(yaml_document_t *doc, yaml_node_t *map_node, const char *key) {
    if (!map_node || map_node->type != YAML_MAPPING_NODE) {
        return NULL;
    }
    for (yaml_node_pair_t *pair = map_node->data.mapping.pairs.start;
         pair < map_node->data.mapping.pairs.top; pair++) {
        yaml_node_t *key_node = yaml_document_get_node(doc, pair->key);
        if (key_node && key_node->type == YAML_SCALAR_NODE &&
            key_node->data.scalar.length == strlen(key) &&
            memcmp(key_node->data.scalar.value, key, key_node->data.scalar.length) == 0) {
            return yaml_document_get_node(doc, pair->value);
        }
    }
    return NULL;
}

static int parse_severity(const char *s, crimp_severity *out) {
    if (strcmp(s, "low") == 0) {
        *out = CRIMP_SEVERITY_LOW;
    } else if (strcmp(s, "medium") == 0) {
        *out = CRIMP_SEVERITY_MEDIUM;
    } else if (strcmp(s, "high") == 0) {
        *out = CRIMP_SEVERITY_HIGH;
    } else if (strcmp(s, "critical") == 0) {
        *out = CRIMP_SEVERITY_CRITICAL;
    } else {
        return -1;
    }
    return 0;
}

static void str_to_lower(char *s) {
    for (; *s; s++) {
        if (*s >= 'A' && *s <= 'Z') {
            *s = (char)(*s - 'A' + 'a');
        }
    }
}

/* Parses one rule entry (a YAML_MAPPING_NODE with id/pattern/description/
 * severity scalar keys) into a freshly heap-allocated crimp_yaml_rule,
 * appended to `out`. Returns 0 on success, -1 if any required field is
 * missing, the wrong node type, or an unrecognized severity value -
 * nothing is left partially allocated on failure. */
static int parse_rule_entry(yaml_document_t *doc, yaml_node_t *entry, crimp_yaml_rule_list *out) {
    char *id = dup_scalar(mapping_get(doc, entry, "id"));
    char *pattern = dup_scalar(mapping_get(doc, entry, "pattern"));
    char *description = dup_scalar(mapping_get(doc, entry, "description"));
    char *severity_str = dup_scalar(mapping_get(doc, entry, "severity"));

    int ok = 0;
    crimp_severity severity = CRIMP_SEVERITY_LOW;
    /* An empty pattern would match every file via strstr(buf, "") - reject
     * it here rather than let it silently flood every scan with a finding
     * on every single file under that rule's id. */
    if (id && pattern && pattern[0] != '\0' && description && severity_str) {
        str_to_lower(severity_str);
        ok = (parse_severity(severity_str, &severity) == 0);
    }
    free(severity_str);

    if (!ok) {
        free(id);
        free(pattern);
        free(description);
        return -1;
    }
    if (rule_list_add(out, id, pattern, description, severity) != 0) {
        free(id);
        free(pattern);
        free(description);
        return -1;
    }
    return 0;
}

int crimp_yaml_rules_load_file(const char *path, crimp_yaml_rule_list *out) {
    FILE *f = fopen(path, "rb");
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
    yaml_node_t *rules_node = mapping_get(&doc, root, "rules");
    if (!rules_node || rules_node->type != YAML_SEQUENCE_NODE) {
        yaml_document_delete(&doc);
        return -1;
    }

    /* Parsed into a temporary list first and only merged into `out` once
     * every entry in this file parses cleanly - a malformed rule later in
     * the file must not leave earlier ones from the same file loaded. */
    crimp_yaml_rule_list parsed;
    crimp_yaml_rule_list_init(&parsed);
    int ok = 1;
    for (yaml_node_item_t *item = rules_node->data.sequence.items.start;
         ok && item < rules_node->data.sequence.items.top; item++) {
        yaml_node_t *entry = yaml_document_get_node(&doc, *item);
        if (!entry || entry->type != YAML_MAPPING_NODE ||
            parse_rule_entry(&doc, entry, &parsed) != 0) {
            ok = 0;
        }
    }
    yaml_document_delete(&doc);

    if (!ok) {
        crimp_yaml_rule_list_free(&parsed);
        return -1;
    }

    for (size_t i = 0; i < parsed.count; i++) {
        if (rule_list_add(out, parsed.items[i].id, parsed.items[i].pattern,
                           parsed.items[i].description, parsed.items[i].severity) != 0) {
            /* Ownership of the remaining un-transferred items stays with
             * `parsed` - free just those, the ones already moved into
             * `out` are now `out`'s to free. */
            for (size_t j = i; j < parsed.count; j++) {
                rule_free(&parsed.items[j]);
            }
            free(parsed.items);
            return -1;
        }
    }
    free(parsed.items); /* ownership of every item's strings moved into out above */
    return 0;
}

/* Case-insensitive suffix compare - a filesystem where filenames are
 * case-sensitive (Linux, a first-class supported build target for this
 * project) would otherwise silently exclude a rule file named e.g.
 * "MyRules.YAML" from crimp_yaml_rules_load_dir below, with no indication
 * to the user that it was skipped purely due to extension casing. */
static int ends_with_ci(const char *name, size_t name_len, const char *suffix) {
    size_t suffix_len = strlen(suffix);
    if (name_len < suffix_len) {
        return 0;
    }
    const char *tail = name + (name_len - suffix_len);
    for (size_t i = 0; i < suffix_len; i++) {
        char c = tail[i];
        if (c >= 'A' && c <= 'Z') {
            c = (char)(c - 'A' + 'a');
        }
        if (c != suffix[i]) {
            return 0;
        }
    }
    return 1;
}

static int has_yaml_extension(const char *name) {
    size_t len = strlen(name);
    return ends_with_ci(name, len, ".yaml") || ends_with_ci(name, len, ".yml");
}

int crimp_yaml_rules_load_dir(const char *dir_path, crimp_yaml_rule_list *out) {
    DIR *d = opendir(dir_path);
    if (!d) {
        return -1;
    }
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        if (!has_yaml_extension(entry->d_name)) {
            continue;
        }
        char path[1024];
        int n = snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);
        if (n < 0 || (size_t)n >= sizeof(path)) {
            continue;
        }
        crimp_yaml_rules_load_file(path, out); /* best-effort: skip a bad file, keep going */
    }
    closedir(d);
    return 0;
}

/* Delegates to the same shared walk+read+match+add loop every other
 * pattern-based detector uses (crimp_scan_directory_for_patterns,
 * pattern_scan.c) instead of re-implementing it - each rule's own `id`
 * becomes its marker's `name` override, so a single walk still reports the
 * right detector_name per rule even though they don't share one batch-wide
 * name the way the built-in detectors do. */
void crimp_scan_directory_for_yaml_rules(const char *root_path, const crimp_yaml_rule_list *rules,
                                          crimp_finding_list *out) {
    if (rules->count == 0) {
        return;
    }
    crimp_pattern_marker *markers =
        (crimp_pattern_marker *)malloc(rules->count * sizeof(crimp_pattern_marker));
    if (!markers) {
        return;
    }
    for (size_t i = 0; i < rules->count; i++) {
        markers[i].pattern = rules->items[i].pattern;
        markers[i].description = rules->items[i].description;
        markers[i].severity = rules->items[i].severity;
        markers[i].name = rules->items[i].id;
    }
    /* `detector_name` is unused here since every marker sets its own
     * `name` above - passed as NULL rather than a real fallback. */
    crimp_scan_directory_for_patterns(root_path, NULL, markers, rules->count, out);
    free(markers);
}
