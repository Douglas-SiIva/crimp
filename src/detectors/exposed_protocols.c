#include "crimp/detectors.h"

#include "core/fileutil.h"
#include "core/walk.h"

#include <stdio.h>
#include <string.h>

#define READ_CHUNK 65536

typedef struct {
    const char *pattern;
    const char *description;
    crimp_severity severity;
} protocol_marker;

static const protocol_marker PROTOCOL_MARKERS[] = {
    {"allow_anonymous true", "MQTT broker allows anonymous (unauthenticated) connections",
     CRIMP_SEVERITY_HIGH},
    {"telnetd", "Telnet daemon referenced — unencrypted remote access", CRIMP_SEVERITY_MEDIUM},
    {"miniupnpd", "UPnP daemon configured — often unnecessary attack surface",
     CRIMP_SEVERITY_LOW},
    {"avahi-daemon", "mDNS/Avahi service configured and reachable", CRIMP_SEVERITY_LOW},
};
#define PROTOCOL_MARKER_COUNT (sizeof(PROTOCOL_MARKERS) / sizeof(PROTOCOL_MARKERS[0]))

static void scan_file(const char *path, void *userdata) {
    crimp_finding_list *out = (crimp_finding_list *)userdata;

    char buf[READ_CHUNK];
    if (crimp_read_file_chunk(path, buf, sizeof(buf)) <= 0) {
        return;
    }

    char desc[1024];

    for (size_t i = 0; i < PROTOCOL_MARKER_COUNT; i++) {
        if (strstr(buf, PROTOCOL_MARKERS[i].pattern)) {
            snprintf(desc, sizeof(desc), "%s (%s)", PROTOCOL_MARKERS[i].description, path);
            crimp_finding_list_add(out, "exposed-protocols", desc, PROTOCOL_MARKERS[i].severity);
        }
    }
}

static void scan(const char *root_path, crimp_finding_list *out) {
    crimp_walk_directory(root_path, scan_file, out);
}

const crimp_detector crimp_detector_exposed_protocols = {
    .name = "exposed-protocols",
    .scan = scan,
};
