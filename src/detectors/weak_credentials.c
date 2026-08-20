#include "crimp/detectors.h"

#include "core/pattern_scan.h"

static const crimp_pattern_marker MARKERS[] = {
    {"-----BEGIN RSA PRIVATE KEY-----", "Embedded private key found", CRIMP_SEVERITY_CRITICAL},
    {"-----BEGIN OPENSSH PRIVATE KEY-----", "Embedded private key found",
     CRIMP_SEVERITY_CRITICAL},
    {"-----BEGIN EC PRIVATE KEY-----", "Embedded private key found", CRIMP_SEVERITY_CRITICAL},
    {"-----BEGIN DSA PRIVATE KEY-----", "Embedded private key found", CRIMP_SEVERITY_CRITICAL},
    {"-----BEGIN PRIVATE KEY-----", "Embedded private key found", CRIMP_SEVERITY_CRITICAL},
    {"password=admin", "Default/weak credential pattern 'password=admin' found",
     CRIMP_SEVERITY_HIGH},
    {"password=password", "Default/weak credential pattern 'password=password' found",
     CRIMP_SEVERITY_HIGH},
    {"password=123456", "Default/weak credential pattern 'password=123456' found",
     CRIMP_SEVERITY_HIGH},
    {"root:root:", "Default/weak credential pattern 'root:root:' found", CRIMP_SEVERITY_HIGH},
    {"admin:admin", "Default/weak credential pattern 'admin:admin' found", CRIMP_SEVERITY_HIGH},
};
#define MARKER_COUNT (sizeof(MARKERS) / sizeof(MARKERS[0]))

static void scan(const char *root_path, crimp_finding_list *out) {
    crimp_scan_directory_for_patterns(root_path, "weak-credentials", MARKERS, MARKER_COUNT, out);
}

const crimp_detector crimp_detector_weak_credentials = {
    .name = "weak-credentials",
    .scan = scan,
};
