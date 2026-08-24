#ifndef CRIMP_CVE_H
#define CRIMP_CVE_H

#include "crimp/detector.h"
#include "crimp/inventory.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Matches already-identified components (crimp/inventory.h) against a local
 * CVE dataset (issue #12) - a YAML file synced offline from NVD by
 * scripts/sync_cve_dataset.py, not fetched live during a scan (the chosen
 * use case is offline/air-gapped scanning). Dataset format:
 *
 *   components:
 *     - name: OpenSSL              # matches crimp_component.component exactly
 *       cves:
 *         - id: CVE-2022-0778
 *           affected: "<1.1.1n"     # see below for the range syntax
 *           severity: high
 *           description: "Infinite loop in BN_mod_sqrt()"
 *
 * `affected` is a comma-separated list of conditions, each `OP VERSION`
 * with OP one of `<`, `<=`, `>`, `>=`, `==` (no spaces required) - a
 * component's version must satisfy every condition (AND) to count as
 * affected. Versions compare component-wise (dot- or hyphen-separated
 * segments, each an optional numeric part followed by an optional
 * lowercase-letter suffix, e.g. "1.1.1n" - the numeric part orders first,
 * the suffix breaks ties, a missing segment sorts as the lowest possible
 * value for that position).
 *
 * crimp_identify_components() extracts the digit/'.'/'-'/lowercase-letter
 * prefix of a version string (src/core/component_identify.c) - enough to
 * capture OpenSSL's classic "1.1.1k"-style trailing patch letter, which an
 * earlier digit/'.'/'-'-only version dropped entirely (a real "1.1.1n"
 * install extracted as just "1.1.1" compared as *older* than any lettered
 * version, over-reporting CVEs already fixed by that patch letter - fixed
 * once this inaccuracy became directly observable through CVE matching).
 * Still approximate for anything not shaped like "digits, separators,
 * trailing letters" - e.g. a build/vendor suffix crimp can't distinguish
 * from a real version segment. */

/* Loads `dataset_path`, matches every component in `components` against it,
 * and appends a finding for each (component instance, CVE) match to `out` -
 * detector_name is the matched CVE's own id (e.g. "CVE-2022-0778"), same
 * "the specific rule's own identity, not a generic label" convention
 * crimp_yaml_rules.h's user-defined rules already use. Returns 0 on success
 * (including "dataset loaded but nothing matched"), -1 if `dataset_path`
 * couldn't be opened or parsed - `out` is left exactly as it was on
 * failure, no partial findings added. */
int crimp_cve_match_components(const char *dataset_path, const crimp_component_list *components,
                                crimp_finding_list *out);

#ifdef __cplusplus
}
#endif

#endif /* CRIMP_CVE_H */
