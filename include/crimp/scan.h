#ifndef CRIMP_SCAN_H
#define CRIMP_SCAN_H

#include "crimp/detector.h"
#include "crimp/inventory.h"
#include "crimp/yaml_rules.h"

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
 * testable) without a subprocess. If `rules_dir` is non-NULL, every
 * *.yaml/*.yml file directly inside it is loaded as additional
 * user-defined pattern rules (see crimp/yaml_rules.h) and run in the same
 * pass, appending to the same `result->findings`. Pass NULL to skip
 * user-defined rules entirely (the original behavior).
 *
 * Returns 0 normally, or -1 if `rules_dir` was given but couldn't be opened
 * (e.g. a typo'd path) - the built-in detectors and component
 * identification still ran and `result` is still fully populated with
 * whatever they found, but silently proceeding with zero user-defined
 * findings when the user asked for some would be a false sense of
 * completeness in a security scanner, so the caller gets a way to notice
 * and warn about it instead of that failure being invisible. */
int crimp_scan_directory(const char *root_path, const char *rules_dir, crimp_scan_result *result);

#ifdef __cplusplus
}
#endif

#endif /* CRIMP_SCAN_H */
