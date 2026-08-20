#include "crimp/scan.h"

#include "crimp/detectors.h"
#include "crimp/registry.h"

void crimp_scan_result_init(crimp_scan_result *result) {
    crimp_finding_list_init(&result->findings);
    crimp_component_list_init(&result->components);
}

void crimp_scan_result_free(crimp_scan_result *result) {
    crimp_finding_list_free(&result->findings);
    crimp_component_list_free(&result->components);
}

void crimp_scan_directory(const char *root_path, crimp_scan_result *result) {
    crimp_registry reg;
    crimp_registry_init(&reg);
    crimp_registry_add(&reg, &crimp_detector_weak_credentials);
    crimp_registry_add(&reg, &crimp_detector_exposed_protocols);
    crimp_registry_add(&reg, &crimp_detector_weak_crypto);

    crimp_registry_run_all(&reg, root_path, &result->findings);
    crimp_identify_components(root_path, &result->components);
}
