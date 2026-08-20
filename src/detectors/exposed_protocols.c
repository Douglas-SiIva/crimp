#include "crimp/detectors.h"

#include "core/pattern_scan.h"

static const crimp_pattern_marker MARKERS[] = {
    {"allow_anonymous true", "MQTT broker allows anonymous (unauthenticated) connections",
     CRIMP_SEVERITY_HIGH},
    {"telnetd", "Telnet daemon referenced — unencrypted remote access", CRIMP_SEVERITY_MEDIUM},
    {"miniupnpd", "UPnP daemon configured — often unnecessary attack surface",
     CRIMP_SEVERITY_LOW},
    {"avahi-daemon", "mDNS/Avahi service configured and reachable", CRIMP_SEVERITY_LOW},
};
#define MARKER_COUNT (sizeof(MARKERS) / sizeof(MARKERS[0]))

static void scan(const char *root_path, crimp_finding_list *out) {
    crimp_scan_directory_for_patterns(root_path, "exposed-protocols", MARKERS, MARKER_COUNT, out);
}

const crimp_detector crimp_detector_exposed_protocols = {
    .name = "exposed-protocols",
    .scan = scan,
};
