#include "crimp/detector.h"

#include <stdlib.h>
#include <string.h>

#define INITIAL_CAPACITY 16

void crimp_finding_list_init(crimp_finding_list *list) {
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

void crimp_finding_list_add(crimp_finding_list *list, const char *detector_name,
                             const char *description, crimp_severity severity) {
    if (list->count == list->capacity) {
        size_t new_capacity = list->capacity == 0 ? INITIAL_CAPACITY : list->capacity * 2;
        list->items = (crimp_finding *)realloc(list->items, new_capacity * sizeof(crimp_finding));
        list->capacity = new_capacity;
    }

    crimp_finding *f = &list->items[list->count++];
    f->detector_name = detector_name; /* detector names are string literals, not owned */
    f->description = strdup(description);
    f->severity = severity;
}

void crimp_finding_list_free(crimp_finding_list *list) {
    for (size_t i = 0; i < list->count; i++) {
        free(list->items[i].description);
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}
