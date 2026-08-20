#ifndef CRIMP_CORE_PATTERN_SCAN_H
#define CRIMP_CORE_PATTERN_SCAN_H

#include <stddef.h>

#include "crimp/detector.h"

typedef struct {
    const char *pattern;
    const char *description;
    crimp_severity severity;
} crimp_pattern_marker;

/* Walks `root_path` and, for every regular file, checks its content against
 * each marker's `pattern` (plain substring match, no regex). On a hit,
 * appends a finding to `out` combining the marker's description with the
 * file path. Shared by every pattern-based detector (weak-credentials,
 * exposed-protocols, weak-crypto, ...). */
void crimp_scan_directory_for_patterns(const char *root_path, const char *detector_name,
                                        const crimp_pattern_marker *markers, size_t marker_count,
                                        crimp_finding_list *out);

#endif /* CRIMP_CORE_PATTERN_SCAN_H */
