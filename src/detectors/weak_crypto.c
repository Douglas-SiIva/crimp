#include "crimp/detectors.h"

#include "core/pattern_scan.h"

static const crimp_pattern_marker MARKERS[] = {
    {"SSLv2", "Obsolete SSLv2 protocol referenced in configuration", CRIMP_SEVERITY_CRITICAL},
    {"SSLv3", "Obsolete SSLv3 protocol referenced in configuration (POODLE)",
     CRIMP_SEVERITY_HIGH},
    {"RC4", "Weak RC4 cipher referenced in configuration", CRIMP_SEVERITY_HIGH},
    {"DES-CBC", "Weak DES cipher referenced in configuration", CRIMP_SEVERITY_HIGH},
    {"NULL-MD5", "Null/MD5 cipher suite referenced in configuration", CRIMP_SEVERITY_HIGH},
};
#define MARKER_COUNT (sizeof(MARKERS) / sizeof(MARKERS[0]))

static void scan(const char *root_path, crimp_finding_list *out) {
    crimp_scan_directory_for_patterns(root_path, "weak-crypto", MARKERS, MARKER_COUNT, out);
}

const crimp_detector crimp_detector_weak_crypto = {
    .name = "weak-crypto",
    .scan = scan,
};
