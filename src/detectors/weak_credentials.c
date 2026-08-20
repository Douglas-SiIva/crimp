#include "crimp/detectors.h"

#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

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

static void scan_file(const char *path, crimp_finding_list *out) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        return;
    }

    char buf[READ_CHUNK];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (n == 0) {
        return;
    }
    buf[n] = '\0';

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

static void walk_directory(const char *dir_path, crimp_finding_list *out) {
    DIR *d = opendir(dir_path);
    if (!d) {
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);

        struct stat st;
        if (stat(path, &st) != 0) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            walk_directory(path, out);
        } else if (S_ISREG(st.st_mode)) {
            scan_file(path, out);
        }
    }

    closedir(d);
}

static void scan(const char *root_path, crimp_finding_list *out) {
    walk_directory(root_path, out);
}

const crimp_detector crimp_detector_weak_credentials = {
    .name = "weak-credentials",
    .scan = scan,
};
