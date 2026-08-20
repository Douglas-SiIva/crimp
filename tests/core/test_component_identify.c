#include "crimp/inventory.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>
#endif

/* Writes fake binary content: some NUL bytes (simulating real executable
 * data), then a version marker, proving the scanner is NUL-safe and not
 * just doing a strstr() over the buffer as if it were a C string. */
static void write_binary_fixture(const char *dir, const char *filename) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dir, filename);

    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "failed to create fixture: %s\n", path);
        exit(1);
    }

    unsigned char prefix[32];
    memset(prefix, 0, sizeof(prefix));
    fwrite(prefix, 1, sizeof(prefix), f);

    fputs("BusyBox v1.31.1 (2021-03-15 12:00:00 UTC) multi-call binary.", f);
    fputc('\0', f);
    fputs("OpenSSL 1.1.1k  25 Mar 2021", f);

    fclose(f);
}

int main(void) {
    const char *fixture_dir = "test_fixture_component_identify";
#ifdef _WIN32
    _mkdir(fixture_dir);
#else
    mkdir(fixture_dir, 0755);
#endif

    write_binary_fixture(fixture_dir, "busybox.bin");

    crimp_component_list components;
    crimp_component_list_init(&components);

    crimp_identify_components(fixture_dir, &components);

    int saw_busybox = 0;
    int saw_openssl = 0;
    for (size_t i = 0; i < components.count; i++) {
        printf("%s %s (%s)\n", components.items[i].component, components.items[i].version,
               components.items[i].path);
        if (strcmp(components.items[i].component, "BusyBox") == 0 &&
            strcmp(components.items[i].version, "1.31.1") == 0) {
            saw_busybox = 1;
        }
        if (strcmp(components.items[i].component, "OpenSSL") == 0 &&
            strcmp(components.items[i].version, "1.1.1") == 0) {
            saw_openssl = 1;
        }
    }

    size_t total = components.count;
    crimp_component_list_free(&components);

    if (!saw_busybox || !saw_openssl) {
        fprintf(stderr,
                "FAIL: expected BusyBox 1.31.1 and OpenSSL 1.1.1 identified, got %zu "
                "component(s)\n",
                total);
        return 1;
    }

    printf("PASS: component identification found both expected components\n");
    return 0;
}
