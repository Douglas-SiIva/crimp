#ifndef CRIMP_YAML_RULES_H
#define CRIMP_YAML_RULES_H

#include "crimp/detector.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* User-defined detector rules loaded from YAML at runtime, no recompiling
 * needed - same idea as Nuclei templates. A rule file looks like:
 *
 *   rules:
 *     - id: custom-telnet-check
 *       description: "Telnet daemon binary referenced"
 *       severity: medium
 *       pattern: "telnetd"
 *
 * `pattern` is matched the same way every built-in pattern-based detector
 * already works (crimp_scan_directory_for_patterns): a plain substring
 * search, no regex. `severity` is one of low/medium/high/critical
 * (case-insensitive). `id` becomes the finding's detector_name, so
 * multiple rules in the same or different files are distinguishable in
 * output. */
typedef struct {
    char *id;
    char *pattern;
    char *description;
    crimp_severity severity;
} crimp_yaml_rule;

typedef struct {
    crimp_yaml_rule *items;
    size_t count;
    size_t capacity;
} crimp_yaml_rule_list;

void crimp_yaml_rule_list_init(crimp_yaml_rule_list *list);
void crimp_yaml_rule_list_free(crimp_yaml_rule_list *list);

/* Parses one YAML rule file, appending every rule it defines to `out` (so
 * it's safe to call repeatedly with the same list to load several files).
 * Malformed YAML, a missing/wrong-type top-level `rules` key, or any rule
 * missing a required field (id/pattern/description/severity) or an
 * unrecognized severity value rejects the *whole file* - nothing from it is
 * added to `out`, rather than silently loading a partial rule set. Returns
 * 0 on success, -1 otherwise (including if `path` can't be opened). */
int crimp_yaml_rules_load_file(const char *path, crimp_yaml_rule_list *out);

/* Loads every top-level *.yaml/*.yml file directly inside `dir_path` (not
 * recursive) into `out`, best-effort: a file that fails to parse is
 * skipped, not fatal to the others. Returns 0 if `dir_path` itself could be
 * opened (even if it contained zero rule files, or every file in it failed
 * to parse), -1 if `dir_path` couldn't be opened at all. */
int crimp_yaml_rules_load_dir(const char *dir_path, crimp_yaml_rule_list *out);

/* Walks `root_path` once, checking every regular file's content against
 * every loaded rule's pattern - a single pass regardless of how many rules
 * are loaded, not one directory walk per rule. Appends a finding per hit,
 * using the matching rule's own `id` as detector_name. */
void crimp_scan_directory_for_yaml_rules(const char *root_path, const crimp_yaml_rule_list *rules,
                                          crimp_finding_list *out);

#ifdef __cplusplus
}
#endif

#endif /* CRIMP_YAML_RULES_H */
