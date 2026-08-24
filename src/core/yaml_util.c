#include "yaml_util.h"

#include <stdlib.h>
#include <string.h>

char *crimp_yaml_dup_scalar(const yaml_node_t *node) {
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

yaml_node_t *crimp_yaml_mapping_get(yaml_document_t *doc, yaml_node_t *map_node,
                                     const char *key) {
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
