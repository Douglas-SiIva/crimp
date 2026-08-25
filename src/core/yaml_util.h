#ifndef CRIMP_YAML_UTIL_H
#define CRIMP_YAML_UTIL_H

#include "crimp/detector.h"

#include <yaml.h>

/* Small libyaml document-tree helpers shared by every YAML-consuming
 * feature (yaml_rules.c, cve_match.c) - originally yaml_rules.c-only,
 * duplicated would-be into cve_match.c had this not been factored out
 * first, same "don't let a second copy happen" discipline already applied
 * to src/extract/fs_util.c. */

/* Copies a scalar node's value into a fresh NUL-terminated heap string.
 * libyaml's scalar values aren't guaranteed NUL-terminated by the API
 * contract - always go through `.length`, never assume it. Returns NULL
 * for a non-scalar node or on allocation failure. */
char *crimp_yaml_dup_scalar(const yaml_node_t *node);

/* Finds `key` among a YAML_MAPPING_NODE's pairs and returns its value node,
 * or NULL if `map_node` isn't a mapping or has no such key. */
yaml_node_t *crimp_yaml_mapping_get(yaml_document_t *doc, const yaml_node_t *map_node,
                                     const char *key);

/* ASCII-only, in place - deliberately not locale-dependent tolower(). */
void crimp_yaml_str_to_lower(char *s);

/* Parses "low"/"medium"/"high"/"critical" (case-sensitive - lowercase `s`
 * with crimp_yaml_str_to_lower() first if it might not already be) into
 * `out`. Returns 0 on success, -1 for anything else - the caller decides
 * what "anything else" means for its own format (yaml_rules.c rejects the
 * whole rule; cve_match.c falls back to LOW rather than silently dropping
 * an otherwise-valid CVE match). */
int crimp_yaml_parse_severity(const char *s, crimp_severity *out);

#endif /* CRIMP_YAML_UTIL_H */
