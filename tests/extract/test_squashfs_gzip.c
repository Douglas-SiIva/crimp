#include "extract_internal.h"

#include <stdio.h>
#include <string.h>

#ifndef FIXTURE_PATH
#error "FIXTURE_PATH must be defined by the build (see CMakeLists.txt)"
#endif

typedef struct {
    const char *path;
    int is_dir;
    unsigned long long size;
} expected_entry;

/* Same tree as squashfs_uncompressed.img (test_squashfs_list.c), but this
 * fixture is genuinely gzip-compressed (`mksquashfs -comp gzip`, no -noI
 * -noD -noF -noX) — exercises real decompression, not just the uncompressed
 * fast path. Ground truth captured from `unsquashfs -l`; see
 * tests/fixtures/README.md for how it was generated and regenerated. */
static const expected_entry EXPECTED[] = {
    {"bin", 1, 0},
    {"bin/busybox", 0, 38},
    {"bin/nested", 1, 0},
    {"bin/nested/deep.txt", 0, 24},
    {"bin/sh", 0, 12}, /* symlink; target "/bin/busybox" is 12 bytes */
    {"etc", 1, 0},
    {"etc/config.txt", 0, 12},
    {"etc/passwd", 0, 30},
};
#define EXPECTED_COUNT (sizeof(EXPECTED) / sizeof(EXPECTED[0]))

static int find_expected(const char *path) {
    for (size_t i = 0; i < EXPECTED_COUNT; i++) {
        if (strcmp(EXPECTED[i].path, path) == 0) {
            return (int)i;
        }
    }
    return -1;
}

int main(void) {
    crimp_squashfs_entry_list list;
    if (crimp_squashfs_list(FIXTURE_PATH, &list) != 0) {
        fprintf(stderr, "FAIL: crimp_squashfs_list failed on %s\n", FIXTURE_PATH);
        return 1;
    }

    if (list.count != EXPECTED_COUNT) {
        fprintf(stderr, "FAIL: expected %zu entries, got %zu\n", EXPECTED_COUNT, list.count);
        crimp_squashfs_entry_list_free(&list);
        return 1;
    }

    int seen[EXPECTED_COUNT];
    memset(seen, 0, sizeof(seen));

    for (size_t i = 0; i < list.count; i++) {
        int idx = find_expected(list.items[i].path);
        if (idx < 0) {
            fprintf(stderr, "FAIL: unexpected entry '%s'\n", list.items[i].path);
            crimp_squashfs_entry_list_free(&list);
            return 1;
        }
        const expected_entry *e = &EXPECTED[idx];
        if (list.items[i].is_dir != e->is_dir ||
            (unsigned long long)list.items[i].size != e->size) {
            fprintf(stderr,
                    "FAIL: entry '%s' mismatch (is_dir=%d size=%llu, expected is_dir=%d "
                    "size=%llu)\n",
                    list.items[i].path, list.items[i].is_dir,
                    (unsigned long long)list.items[i].size, e->is_dir, e->size);
            crimp_squashfs_entry_list_free(&list);
            return 1;
        }
        seen[idx] = 1;
    }

    crimp_squashfs_entry_list_free(&list);

    for (size_t i = 0; i < EXPECTED_COUNT; i++) {
        if (!seen[i]) {
            fprintf(stderr, "FAIL: expected entry '%s' was not found\n", EXPECTED[i].path);
            return 1;
        }
    }

    printf("PASS: crimp_squashfs_list matches unsquashfs -l ground truth (gzip-compressed)\n");
    return 0;
}
