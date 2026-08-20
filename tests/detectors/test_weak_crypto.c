#include "crimp/detectors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>
#endif

static void write_fixture(const char *dir, const char *filename, const char *content) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dir, filename);

    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "failed to create fixture: %s\n", path);
        exit(1);
    }
    fputs(content, f);
    fclose(f);
}

int main(void) {
    const char *fixture_dir = "test_fixture_weak_crypto";
#ifdef _WIN32
    _mkdir(fixture_dir);
#else
    mkdir(fixture_dir, 0755);
#endif

    write_fixture(fixture_dir, "stunnel.conf", "protocol = SSLv3\nciphers = RC4-MD5\n");

    crimp_finding_list findings;
    crimp_finding_list_init(&findings);

    crimp_detector_weak_crypto.scan(fixture_dir, &findings);

    int saw_sslv3_finding = 0;
    int saw_rc4_finding = 0;
    for (size_t i = 0; i < findings.count; i++) {
        printf("[%s] %s\n", findings.items[i].detector_name, findings.items[i].description);
        if (strstr(findings.items[i].description, "SSLv3")) {
            saw_sslv3_finding = 1;
        }
        if (strstr(findings.items[i].description, "RC4")) {
            saw_rc4_finding = 1;
        }
    }

    size_t total_findings = findings.count;
    crimp_finding_list_free(&findings);

    if (!saw_sslv3_finding || !saw_rc4_finding) {
        fprintf(stderr,
                "FAIL: expected both an SSLv3 finding and an RC4 finding, got %zu finding(s)\n",
                total_findings);
        return 1;
    }

    printf("PASS: weak-crypto detector found both expected findings\n");
    return 0;
}
