#ifndef CRIMP_YAML_UTIL_H
#define CRIMP_YAML_UTIL_H

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
yaml_node_t *crimp_yaml_mapping_get(yaml_document_t *doc, yaml_node_t *map_node, const char *key);

#endif /* CRIMP_YAML_UTIL_H */
