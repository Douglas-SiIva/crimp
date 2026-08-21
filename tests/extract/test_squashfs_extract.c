#include "extract_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef FIXTURE_PATH
#error "FIXTURE_PATH must be defined by the build (see CMakeLists.txt)"
#endif
#ifndef OUTPUT_DIR
#error "OUTPUT_DIR must be defined by the build (see CMakeLists.txt)"
#endif

/* Ground truth captured from `unsquashfs -d` + sha256sum against this
 * fixture — see tests/fixtures/README.md for how it was generated. */
static const char EXPECTED_CONFIG[] = "hello=world\n";
static const char EXPECTED_PASSWD[] = "root:x:0:0:root:/root:/bin/sh\n";
static const char EXPECTED_BUSYBOX[] = "FAKE_BUSYBOX_BINARY_CONTENT_1234567890";
static const char EXPECTED_DEEP[] = "nested file content here";
#define BIGFILE_SIZE 11000

static unsigned char *read_whole_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size < 0) {
        fclose(f);
        return NULL;
    }
    unsigned char *buf = (unsigned char *)malloc((size_t)size + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t n = fread(buf, 1, (size_t)size, f);
    fclose(f);
    if (n != (size_t)size) {
        free(buf);
        return NULL;
    }
    *out_len = n;
    return buf;
}

static int check_file(const char *rel_path, const void *expected, size_t expected_len) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", OUTPUT_DIR, rel_path);
    size_t len = 0;
    unsigned char *buf = read_whole_file(path, &len);
    if (!buf) {
        fprintf(stderr, "FAIL: could not read extracted file '%s'\n", path);
        return 0;
    }
    int ok = (len == expected_len) && (memcmp(buf, expected, expected_len) == 0);
    if (!ok) {
        fprintf(stderr, "FAIL: '%s' content mismatch (got %zu bytes, expected %zu)\n", path, len,
                expected_len);
    }
    free(buf);
    return ok;
}

int main(void) {
    crimp_squashfs_entry_list list;
    if (crimp_squashfs_extract(FIXTURE_PATH, OUTPUT_DIR, &list) != 0) {
        fprintf(stderr, "FAIL: crimp_squashfs_extract failed on %s\n", FIXTURE_PATH);
        return 1;
    }
    crimp_squashfs_entry_list_free(&list);

    int ok = 1;
    ok &= check_file("etc/config.txt", EXPECTED_CONFIG, sizeof(EXPECTED_CONFIG) - 1);
    ok &= check_file("etc/passwd", EXPECTED_PASSWD, sizeof(EXPECTED_PASSWD) - 1);
    ok &= check_file("bin/busybox", EXPECTED_BUSYBOX, sizeof(EXPECTED_BUSYBOX) - 1);
    ok &= check_file("bin/nested/deep.txt", EXPECTED_DEEP, sizeof(EXPECTED_DEEP) - 1);

    /* bigfile.bin: deterministic repeating "0123456789" pattern, 11000
     * bytes, built with a 4KiB block size so it spans two full data blocks
     * plus a fragment-packed tail - exercises block_sizes[] parsing and
     * the fragment table lookup in the same test. */
    unsigned char expected_big[BIGFILE_SIZE];
    for (size_t i = 0; i < BIGFILE_SIZE; i++) {
        expected_big[i] = (unsigned char)('0' + (i % 10));
    }
    ok &= check_file("bin/bigfile.bin", expected_big, BIGFILE_SIZE);

    /* bin/sh is a symlink in the fixture - milestone 2b only extracts
     * regular file content, so nothing should have been written for it. */
    char symlink_path[1024];
    snprintf(symlink_path, sizeof(symlink_path), "%s/bin/sh", OUTPUT_DIR);
    FILE *sh = fopen(symlink_path, "rb");
    if (sh) {
        fprintf(stderr, "FAIL: '%s' should not exist (symlink content isn't extracted)\n",
                symlink_path);
        fclose(sh);
        ok = 0;
    }

    if (!ok) {
        return 1;
    }
    printf("PASS: crimp_squashfs_extract content matches unsquashfs -d ground truth\n");
    return 0;
}
