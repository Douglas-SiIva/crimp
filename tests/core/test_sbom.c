#include "crimp/sbom.h"

#include <stdio.h>
#include <string.h>

int main(void) {
    crimp_component_list components;
    crimp_component_list_init(&components);
    crimp_component_list_add(&components, "OpenSSL", "1.1.1", "/rootfs/usr/lib/libssl.so");
    crimp_component_list_add(&components, "BusyBox", "1.31.1", "/rootfs/bin/busybox");

    const char *tmp_path = "test_sbom_output.json";
    FILE *f = fopen(tmp_path, "wb");
    if (!f) {
        fprintf(stderr, "failed to open %s for writing\n", tmp_path);
        return 1;
    }
    crimp_sbom_write_cyclonedx(&components, f);
    fclose(f);

    crimp_component_list_free(&components);

    f = fopen(tmp_path, "rb");
    if (!f) {
        fprintf(stderr, "failed to reopen %s\n", tmp_path);
        return 1;
    }
    char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';

    const char *required[] = {
        "\"bomFormat\": \"CycloneDX\"",
        "\"specVersion\": \"1.6\"",
        "\"OpenSSL\"",
        "\"1.1.1\"",
        "\"BusyBox\"",
        "\"1.31.1\"",
        "libssl.so",
        "busybox",
    };
    size_t required_count = sizeof(required) / sizeof(required[0]);

    for (size_t i = 0; i < required_count; i++) {
        if (!strstr(buf, required[i])) {
            fprintf(stderr, "FAIL: expected SBOM output to contain '%s'\n", required[i]);
            return 1;
        }
    }

    printf("PASS: CycloneDX SBOM contains all expected fields\n");
    return 0;
}
