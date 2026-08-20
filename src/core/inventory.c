#include "crimp/inventory.h"

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
    snprintf(c->version, sizeof(c->version), "%s", version);
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
