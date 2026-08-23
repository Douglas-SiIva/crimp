#ifndef CRIMP_CORE_PATTERN_SCAN_H
#define CRIMP_CORE_PATTERN_SCAN_H

#include <stddef.h>

#include "crimp/detector.h"

typedef struct {
    const char *pattern;
    const char *description;
    crimp_severity severity;
    /* Optional per-marker detector_name override - NULL uses the shared
     * `detector_name` passed to crimp_scan_directory_for_patterns() below.
     * Exists so a single walk can also serve callers where every marker
     * needs its *own* distinct name (crimp_scan_directory_for_yaml_rules,
     * where each user-defined rule's `id` is its own detector_name) without
     * re-implementing this same walk+read+match+add loop a second time. */
    const char *name;
} crimp_pattern_marker;

/* Walks `root_path` and, for every regular file, checks its content against
 * each marker's `pattern` (plain substring match, no regex). On a hit,
 * appends a finding to `out` combining the marker's description with the
 * file path, using the marker's own `name` if set or `detector_name`
 * otherwise. Shared by every pattern-based detector (weak-credentials,
 * exposed-protocols, weak-crypto, ...) and by the YAML rule engine. */
void crimp_scan_directory_for_patterns(const char *root_path, const char *detector_name,
                                        const crimp_pattern_marker *markers, size_t marker_count,
                                        crimp_finding_list *out);

#endif /* CRIMP_CORE_PATTERN_SCAN_H */
