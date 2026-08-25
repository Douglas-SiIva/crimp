#ifndef CRIMP_SCAN_H
#define CRIMP_SCAN_H

#include "crimp/cve.h"
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

/* Bits in crimp_scan_directory()'s return value - which optional input
 * failed, not just whether *something* did. Two independent optional
 * inputs (rules_dir, cve_dataset_path) can each fail on their own; a
 * single -1 sentinel couldn't tell a caller which one without probing the
 * paths itself, so the caller (the CLI) knew to warn about a path that
 * had actually loaded fine. */
#define CRIMP_SCAN_RULES_FAILED (1 << 0)
#define CRIMP_SCAN_CVE_DATASET_FAILED (1 << 1)

/* Registers every built-in detector, runs them all against `root_path`, and
 * identifies components. This is the orchestration the CLI wraps with
 * argument parsing and printing — kept in the library so it's usable (and
 * testable) without a subprocess. If `rules_dir` is non-NULL, every
 * *.yaml or *.yml file directly inside it is loaded as additional
 * user-defined pattern rules (see crimp/yaml_rules.h) and run in the same
 * pass, appending to the same `result->findings`. Pass NULL to skip
 * user-defined rules entirely (the original behavior). If
 * `cve_dataset_path` is non-NULL, identified components are matched
 * against it (see crimp/cve.h) once component identification finishes,
 * appending any (component, CVE) matches to the same `result->findings`.
 * Pass NULL to skip CVE matching entirely.
 *
 * Returns 0 normally, or a bitwise-OR of CRIMP_SCAN_RULES_FAILED and/or
 * CRIMP_SCAN_CVE_DATASET_FAILED if the corresponding path was given but
 * couldn't be opened/parsed (e.g. a typo'd path) - everything else still
 * ran and `result` is still fully populated with whatever it found, but
 * silently proceeding with an incomplete finding set when the user asked
 * for more would be a false sense of completeness in a security scanner,
 * so the caller gets a way to notice and warn about *which* input failed
 * instead of that failure being invisible or ambiguous. */
int crimp_scan_directory(const char *root_path, const char *rules_dir,
                          const char *cve_dataset_path, crimp_scan_result *result);

#ifdef __cplusplus
}
#endif

#endif /* CRIMP_SCAN_H */
