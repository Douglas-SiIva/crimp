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

yaml_node_t *crimp_yaml_mapping_get(yaml_document_t *doc, const yaml_node_t *map_node,
                                     const char *key) {
    if (!map_node || map_node->type != YAML_MAPPING_NODE) {
        return NULL;
    }
    for (const yaml_node_pair_t *pair = map_node->data.mapping.pairs.start;
         pair < map_node->data.mapping.pairs.top; pair++) {
        const yaml_node_t *key_node = yaml_document_get_node(doc, pair->key);
        if (key_node && key_node->type == YAML_SCALAR_NODE &&
            key_node->data.scalar.length == strlen(key) &&
            memcmp(key_node->data.scalar.value, key, key_node->data.scalar.length) == 0) {
            return yaml_document_get_node(doc, pair->value);
        }
    }
    return NULL;
}

void crimp_yaml_str_to_lower(char *s) {
    for (; *s; s++) {
        if (*s >= 'A' && *s <= 'Z') {
            *s = (char)(*s - 'A' + 'a');
        }
    }
}

int crimp_yaml_parse_severity(const char *s, crimp_severity *out) {
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
