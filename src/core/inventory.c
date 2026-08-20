#include "crimp/inventory.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INITIAL_CAPACITY 16

void crimp_component_list_init(crimp_component_list *list) {
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

void crimp_component_list_add(crimp_component_list *list, const char *component,
                               const char *version, const char *path) {
    if (list->count == list->capacity) {
        size_t new_capacity = list->capacity == 0 ? INITIAL_CAPACITY : list->capacity * 2;
        list->items =
            (crimp_component *)realloc(list->items, new_capacity * sizeof(crimp_component));
        list->capacity = new_capacity;
    }

    crimp_component *c = &list->items[list->count++];
    c->component = component; /* string literal, not owned */

    /* `version` may originate from scanned firmware content — filter out
     * non-printable bytes so it can't be used to forge log/report output
     * (e.g. embedded newlines or control sequences) regardless of whether
     * the caller already sanitized it. */
    size_t vi = 0;
    for (size_t i = 0; version[i] != '\0' && vi < sizeof(c->version) - 1; i++) {
        if (isprint((unsigned char)version[i])) {
            c->version[vi++] = version[i];
        }
    }
    c->version[vi] = '\0';

    c->path = strdup(path);
}

void crimp_component_list_free(crimp_component_list *list) {
    for (size_t i = 0; i < list->count; i++) {
        free(list->items[i].path);
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}
