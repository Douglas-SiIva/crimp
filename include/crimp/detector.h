#ifndef CRIMP_DETECTOR_H
#define CRIMP_DETECTOR_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CRIMP_SEVERITY_LOW = 0,
    CRIMP_SEVERITY_MEDIUM,
    CRIMP_SEVERITY_HIGH,
    CRIMP_SEVERITY_CRITICAL,
} crimp_severity;

typedef struct {
    char *detector_name; /* owned copy — see crimp_finding_list_add */
    char *description;   /* owned copy — see crimp_finding_list_add */
    crimp_severity severity;
} crimp_finding;

typedef struct {
    crimp_finding *items;
    size_t count;
    size_t capacity;
} crimp_finding_list;

void crimp_finding_list_init(crimp_finding_list *list);

/* Both `detector_name` and `description` are copied (the list owns its own
 * storage) — safe to pass a stack buffer, a string literal, or a heap
 * string you free right after this call either way. Copying
 * `detector_name` too (not just `description`) matters now that a caller
 * can be a runtime-loaded YAML rule's own `id` (crimp_yaml_rules.c) rather
 * than always a compiled-in string literal — an un-copied pointer would
 * dangle once the rule that produced it is freed, the same class of
 * caller-side-invariant mistake this project has already been burned by
 * once (see crimp_fs_path_component_is_safe's history). */
void crimp_finding_list_add(crimp_finding_list *list, const char *detector_name,
                             const char *description, crimp_severity severity);
void crimp_finding_list_free(crimp_finding_list *list);

/* A detector inspects the extracted firmware tree rooted at `root_path` and
 * appends any findings to `out`. Implementations live in src/detectors/. */
typedef struct {
    const char *name;
    void (*scan)(const char *root_path, crimp_finding_list *out);
} crimp_detector;

#ifdef __cplusplus
}
#endif

#endif /* CRIMP_DETECTOR_H */
