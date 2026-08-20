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
    const char *fixture_dir = "test_fixture_exposed_protocols";
#ifdef _WIN32
    _mkdir(fixture_dir);
#else
    mkdir(fixture_dir, 0755);
#endif

    write_fixture(fixture_dir, "mosquitto.conf", "listener 1883\nallow_anonymous true\n");
    write_fixture(fixture_dir, "inetd.conf", "telnet stream tcp nowait root /usr/sbin/telnetd\n");

    crimp_finding_list findings;
    crimp_finding_list_init(&findings);

    crimp_detector_exposed_protocols.scan(fixture_dir, &findings);

    int saw_mqtt_finding = 0;
    int saw_telnet_finding = 0;
    for (size_t i = 0; i < findings.count; i++) {
        printf("[%s] %s\n", findings.items[i].detector_name, findings.items[i].description);
        if (strstr(findings.items[i].description, "MQTT")) {
            saw_mqtt_finding = 1;
        }
        if (strstr(findings.items[i].description, "Telnet")) {
            saw_telnet_finding = 1;
        }
    }

    size_t total_findings = findings.count;
    crimp_finding_list_free(&findings);

    if (!saw_mqtt_finding || !saw_telnet_finding) {
        fprintf(stderr,
                "FAIL: expected both an MQTT finding and a Telnet finding, got %zu finding(s)\n",
                total_findings);
        return 1;
    }

    printf("PASS: exposed-protocols detector found both expected findings\n");
    return 0;
}
