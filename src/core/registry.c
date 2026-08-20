#include "crimp/registry.h"

void crimp_registry_init(crimp_registry *reg) {
    reg->count = 0;
}

int crimp_registry_add(crimp_registry *reg, const crimp_detector *det) {
    if (reg->count >= CRIMP_MAX_DETECTORS) {
        return -1;
    }
    reg->detectors[reg->count++] = det;
    return 0;
}

void crimp_registry_run_all(const crimp_registry *reg, const char *root_path,
                             crimp_finding_list *out) {
    for (size_t i = 0; i < reg->count; i++) {
        reg->detectors[i]->scan(root_path, out);
    }
}
