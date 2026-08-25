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

int crimp_scan_directory(const char *root_path, const char *rules_dir,
                          const char *cve_dataset_path, crimp_scan_result *result) {
    crimp_registry reg;
    crimp_registry_init(&reg);
    crimp_registry_add(&reg, &crimp_detector_weak_credentials);
    crimp_registry_add(&reg, &crimp_detector_exposed_protocols);
    crimp_registry_add(&reg, &crimp_detector_weak_crypto);

    crimp_registry_run_all(&reg, root_path, &result->findings);
    crimp_identify_components(root_path, &result->components);

    int rc = 0;
    if (rules_dir != NULL) {
        crimp_yaml_rule_list rules;
        crimp_yaml_rule_list_init(&rules);
        if (crimp_yaml_rules_load_dir(rules_dir, &rules) != 0) {
            rc |= CRIMP_SCAN_RULES_FAILED;
        }
        crimp_scan_directory_for_yaml_rules(root_path, &rules, &result->findings);
        crimp_yaml_rule_list_free(&rules);
    }

    if (cve_dataset_path != NULL &&
        crimp_cve_match_components(cve_dataset_path, &result->components, &result->findings) != 0) {
        rc |= CRIMP_SCAN_CVE_DATASET_FAILED;
    }

    return rc;
}
