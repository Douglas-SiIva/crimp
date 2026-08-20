#ifndef CRIMP_REGISTRY_H
#define CRIMP_REGISTRY_H

#include "crimp/detector.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CRIMP_MAX_DETECTORS 64

typedef struct {
    const crimp_detector *detectors[CRIMP_MAX_DETECTORS];
    size_t count;
} crimp_registry;

void crimp_registry_init(crimp_registry *reg);

/* Returns 0 on success, -1 if the registry is full. */
int crimp_registry_add(crimp_registry *reg, const crimp_detector *det);

void crimp_registry_run_all(const crimp_registry *reg, const char *root_path,
                             crimp_finding_list *out);

#ifdef __cplusplus
}
#endif

#endif /* CRIMP_REGISTRY_H */
