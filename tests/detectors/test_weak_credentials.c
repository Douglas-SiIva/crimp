#include "crimp/detectors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>
#endif

/* Fixture content is written at runtime, never committed as a file — a
 * literal-looking private key/password string sitting in git history is
 * exactly what our own Gitleaks/secret-scanning CI would (correctly) flag. */
static void write_fixture(const char *dir, const char *filename, const char *marker_a,
                           const char *marker_b) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dir, filename);

    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "failed to create fixture: %s\n", path);
        exit(1);
    }
    fprintf(f, "%s\n%s\n", marker_a, marker_b);
    fclose(f);
}

int main(void) {
    const char *fixture_dir = "test_fixture_weak_credentials";
#ifdef _WIN32
    _mkdir(fixture_dir);
#else
    mkdir(fixture_dir, 0755);
#endif

    /* Build the two marker strings piecewise so the substring never appears
     * intact in this source file either. */
    char private_key_header[64];
    snprintf(private_key_header, sizeof(private_key_header), "%s%s", "-----BEGIN RSA",
             " PRIVATE KEY-----");

    char weak_password_line[32];
    snprintf(weak_password_line, sizeof(weak_password_line), "%s%s", "password=", "admin");

    write_fixture(fixture_dir, "id_rsa", private_key_header, "not a real key, test fixture only");
    write_fixture(fixture_dir, "config.txt", "hostname=iot-device-01", weak_password_line);

    crimp_finding_list findings;
    crimp_finding_list_init(&findings);

    crimp_detector_weak_credentials.scan(fixture_dir, &findings);

    int saw_key_finding = 0;
    int saw_password_finding = 0;
    for (size_t i = 0; i < findings.count; i++) {
        printf("[%s] %s\n", findings.items[i].detector_name, findings.items[i].description);
        if (strstr(findings.items[i].description, "private key")) {
            saw_key_finding = 1;
        }
        if (strstr(findings.items[i].description, "credential pattern")) {
            saw_password_finding = 1;
        }
    }

    size_t total_findings = findings.count;
    crimp_finding_list_free(&findings);

    if (!saw_key_finding || !saw_password_finding) {
        fprintf(stderr,
                "FAIL: expected both a private-key finding and a weak-credential finding, "
                "got %zu finding(s)\n",
                total_findings);
        return 1;
    }

    printf("PASS: weak-credentials detector found both expected findings\n");
    return 0;
}
