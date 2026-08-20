#ifndef CRIMP_SCAN_H
#define CRIMP_SCAN_H

#include "crimp/detector.h"
#include "crimp/inventory.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Result of running every built-in detector plus component identification
 * against an already-extracted firmware tree. Owns its own storage. */
typedef struct {
    crimp_finding_list findings;
    crimp_component_list components;
} crimp_scan_result;

void crimp_scan_result_init(crimp_scan_result *result);
void crimp_scan_result_free(crimp_scan_result *result);

/* Registers every built-in detector, runs them all against `root_path`, and
 * identifies components. This is the orchestration the CLI wraps with
 * argument parsing and printing — kept in the library so it's usable (and
 * testable) without a subprocess. */
void crimp_scan_directory(const char *root_path, crimp_scan_result *result);

#ifdef __cplusplus
}
#endif

#endif /* CRIMP_SCAN_H */
