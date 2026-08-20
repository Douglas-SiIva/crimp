#include "crimp/detectors.h"

#include "core/fileutil.h"
#include "core/walk.h"

#include <stdio.h>
#include <string.h>

#define READ_CHUNK 65536

static const char *PRIVATE_KEY_MARKERS[] = {
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
};
#define PRIVATE_KEY_MARKER_COUNT (sizeof(PRIVATE_KEY_MARKERS) / sizeof(PRIVATE_KEY_MARKERS[0]))

static const char *DEFAULT_CREDENTIAL_MARKERS[] = {
    "password=admin", "password=password", "password=123456", "root:root:", "admin:admin",
};
#define DEFAULT_CREDENTIAL_MARKER_COUNT \
    (sizeof(DEFAULT_CREDENTIAL_MARKERS) / sizeof(DEFAULT_CREDENTIAL_MARKERS[0]))

static void scan_file(const char *path, void *userdata) {
    crimp_finding_list *out = (crimp_finding_list *)userdata;

    char buf[READ_CHUNK];
    if (crimp_read_file_chunk(path, buf, sizeof(buf)) <= 0) {
        return;
    }

    char desc[1024];

    for (size_t i = 0; i < PRIVATE_KEY_MARKER_COUNT; i++) {
        if (strstr(buf, PRIVATE_KEY_MARKERS[i])) {
            snprintf(desc, sizeof(desc), "Embedded private key found in %s", path);
            crimp_finding_list_add(out, "weak-credentials", desc, CRIMP_SEVERITY_CRITICAL);
        }
    }

    for (size_t i = 0; i < DEFAULT_CREDENTIAL_MARKER_COUNT; i++) {
        if (strstr(buf, DEFAULT_CREDENTIAL_MARKERS[i])) {
            snprintf(desc, sizeof(desc), "Default/weak credential pattern '%s' found in %s",
                     DEFAULT_CREDENTIAL_MARKERS[i], path);
            crimp_finding_list_add(out, "weak-credentials", desc, CRIMP_SEVERITY_HIGH);
        }
    }
}

static void scan(const char *root_path, crimp_finding_list *out) {
    crimp_walk_directory(root_path, scan_file, out);
}

const crimp_detector crimp_detector_weak_credentials = {
    .name = "weak-credentials",
    .scan = scan,
};
