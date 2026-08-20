#include "crimp/scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>
#endif

/* Fixture content is written at runtime, never committed as a file — see the
 * same rationale in tests/detectors/test_weak_credentials.c. */
static void write_credential_fixture(const char *dir) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/config.txt", dir);

    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "failed to create fixture: %s\n", path);
        exit(1);
    }

    char weak_password_line[32];
    snprintf(weak_password_line, sizeof(weak_password_line), "%s%s", "password=", "admin");
    fprintf(f, "hostname=iot-device-01\n%s\n", weak_password_line);
    fclose(f);
}

static void write_component_fixture(const char *dir) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/busybox.bin", dir);

    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "failed to create fixture: %s\n", path);
        exit(1);
    }
    fputs("BusyBox v1.31.1 (2021-03-15 12:00:00 UTC) multi-call binary.", f);
    fclose(f);
}

int main(void) {
    const char *fixture_dir = "test_fixture_scan";
#ifdef _WIN32
    _mkdir(fixture_dir);
#else
    mkdir(fixture_dir, 0755);
#endif

    write_credential_fixture(fixture_dir);
    write_component_fixture(fixture_dir);

    crimp_scan_result result;
    crimp_scan_result_init(&result);
    crimp_scan_directory(fixture_dir, &result);

    int saw_finding = result.findings.count > 0;

    int saw_busybox = 0;
    for (size_t i = 0; i < result.components.count; i++) {
        if (strcmp(result.components.items[i].component, "BusyBox") == 0) {
            saw_busybox = 1;
        }
    }

    size_t finding_count = result.findings.count;
    size_t component_count = result.components.count;
    crimp_scan_result_free(&result);

    if (!saw_finding || !saw_busybox) {
        fprintf(stderr,
                "FAIL: expected at least one finding and a BusyBox component, got %zu "
                "finding(s), %zu component(s)\n",
                finding_count, component_count);
        return 1;
    }

    printf("PASS: crimp_scan_directory wires detectors and component identification together\n");
    return 0;
}
