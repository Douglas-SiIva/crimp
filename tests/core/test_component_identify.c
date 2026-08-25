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

/* Regression for a real miss found scanning an actual device image: a
 * marker followed by a real version string can sit past a small fixed
 * read window. Pads well past the old 256KB cap before placing the
 * marker, so this only passes if the whole file (or at least well past
 * 256KB) is actually scanned. */
static void write_large_offset_fixture(const char *dir, const char *filename) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dir, filename);

    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "failed to create fixture: %s\n", path);
        exit(1);
    }

    unsigned char filler[1024];
    memset(filler, 'A', sizeof(filler));
    /* ~300KB of filler, comfortably past the old 256KB READ_CHUNK. */
    for (int i = 0; i < 300; i++) {
        fwrite(filler, 1, sizeof(filler), f);
    }

    fputs("BusyBox v1.33.0 (2022-01-01 00:00:00 UTC) multi-call binary.", f);

    fclose(f);
}

/* Regression for a real miss found scanning an actual device image
 * (GL.iNet GL-MT300N-V2, OpenWrt 19.07.7): mirrors the real
 * `usr/sbin/dropbear` binary's layout exactly. None of the "dropbear_"
 * marker occurrences (config path, SSH ident) are directly followed by a
 * version - the real version ("2019.78") is a separate, isolated string
 * constant that happens to be string-pool-adjacent to unrelated text
 * ("Dropbear SSH client v%s ..."), never concatenated with "dropbear_".
 * A naive "keep scanning marker occurrences for one followed by a
 * version" fix (the first attempt at this bug) still finds nothing here
 * - only find_isolated_dropbear_version()'s whole-buffer scan for the
 * version's own CalVer shape does. */
static void write_dropbear_fixture(const char *dir, const char *filename) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dir, filename);

    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "failed to create fixture: %s\n", path);
        exit(1);
    }

    fputs("/etc/dropbear/dropbear_rsa_host_key", f);
    fputc('\0', f);
    fputs("SSH-2.0-dropbear", f);
    fputs("\r\n", f);
    fputc('\0', f);
    fputs("2019.78", f);
    fputc('\0', f);
    fputs("Dropbear SSH client v%s https://matt.ucc.asn.au/dropbear/dropbear.html", f);

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
    write_large_offset_fixture(fixture_dir, "busybox_large.bin");
    write_dropbear_fixture(fixture_dir, "dropbear.bin");

    crimp_component_list components;
    crimp_component_list_init(&components);

    crimp_identify_components(fixture_dir, &components);

    int saw_busybox = 0;
    int saw_openssl = 0;
    int saw_busybox_large_offset = 0;
    int saw_dropbear = 0;
    for (size_t i = 0; i < components.count; i++) {
        printf("%s %s (%s)\n", components.items[i].component, components.items[i].version,
               components.items[i].path);
        if (strcmp(components.items[i].component, "BusyBox") == 0 &&
            strcmp(components.items[i].version, "1.31.1") == 0) {
            saw_busybox = 1;
        }
        if (strcmp(components.items[i].component, "OpenSSL") == 0 &&
            strcmp(components.items[i].version, "1.1.1k") == 0) {
            saw_openssl = 1;
        }
        if (strcmp(components.items[i].component, "BusyBox") == 0 &&
            strcmp(components.items[i].version, "1.33.0") == 0) {
            saw_busybox_large_offset = 1;
        }
        if (strcmp(components.items[i].component, "Dropbear") == 0 &&
            strcmp(components.items[i].version, "2019.78") == 0) {
            saw_dropbear = 1;
        }
    }

    size_t total = components.count;
    crimp_component_list_free(&components);

    if (!saw_busybox || !saw_openssl || !saw_busybox_large_offset || !saw_dropbear) {
        fprintf(stderr,
                "FAIL: expected BusyBox 1.31.1, OpenSSL 1.1.1k, BusyBox 1.33.0 (large offset), "
                "and Dropbear 2019.78 (marker adjacency) identified, got %zu component(s)\n",
                total);
        return 1;
    }

    printf("PASS: component identification found all expected components\n");
    return 0;
}
