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
    const char *detector_name;
    const char *description;
    crimp_severity severity;
} crimp_finding;

typedef struct {
    crimp_finding *items;
    size_t count;
    size_t capacity;
} crimp_finding_list;

void crimp_finding_list_init(crimp_finding_list *list);
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
