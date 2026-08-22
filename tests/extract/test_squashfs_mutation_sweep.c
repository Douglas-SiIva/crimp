#include "extract_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <direct.h>
#else
#include <sys/stat.h>
#endif

#ifndef FIXTURE_PATH
#error "FIXTURE_PATH must be defined by the build (see CMakeLists.txt)"
#endif
#ifndef WORK_FILE
#error "WORK_FILE must be defined by the build (see CMakeLists.txt)"
#endif
#ifndef OUTPUT_DIR
#error "OUTPUT_DIR must be defined by the build (see CMakeLists.txt)"
#endif

/* Deterministic mutation sweep over a real, valid SquashFS fixture: every
 * byte offset is set to 0x00 and to 0xFF in turn, and each resulting
 * (almost always malformed) image is run through both public entry points.
 * This isn't a correctness test - nothing about a mutated image's expected
 * output is known - it's a crash-safety and coverage sweep, deliberately
 * reproducible (no RNG/seed) so CI sees the same result every run, unlike
 * this session's ad hoc randomized fuzzing (150k+ iterations, 0 crashes,
 * not part of the committed suite). Every single-byte corruption of a
 * feature-rich fixture (multi-block file, shared fragment, nested dirs)
 * exercises a wide spread of the parser's defensive "malformed input"
 * branches that a hand-written fixture per branch would take dozens of
 * files to reach individually. */

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
    unsigned char *buf = (unsigned char *)malloc((size_t)size);
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

static void make_scratch_dir(const char *path) {
#if defined(_WIN32)
    _mkdir(path);
#else
    mkdir(path, 0700);
#endif
}

int main(void) {
    size_t len = 0;
    unsigned char *original = read_whole_file(FIXTURE_PATH, &len);
    if (!original) {
        fprintf(stderr, "FAIL: could not read fixture %s\n", FIXTURE_PATH);
        return 1;
    }

    make_scratch_dir(OUTPUT_DIR);

    unsigned char *mutated = (unsigned char *)malloc(len);
    if (!mutated) {
        free(original);
        fprintf(stderr, "FAIL: out of memory\n");
        return 1;
    }

    const unsigned char values[] = {0x00, 0xFF};
    long iterations = 0;
    for (size_t offset = 0; offset < len; offset++) {
        for (size_t v = 0; v < sizeof(values); v++) {
            if (original[offset] == values[v]) {
                continue; /* not actually a mutation */
            }
            memcpy(mutated, original, len);
            mutated[offset] = values[v];

            FILE *out = fopen(WORK_FILE, "wb");
            if (!out) {
                fprintf(stderr, "FAIL: could not write %s\n", WORK_FILE);
                free(mutated);
                free(original);
                return 1;
            }
            fwrite(mutated, 1, len, out);
            fclose(out);

            /* Neither call's return value is checked - a mutated image is
             * expected to often be rejected (-1) and occasionally still
             * parse (0, if the flipped byte didn't land somewhere that
             * changes structure). Reaching this line at all, for every one
             * of these variants, is the actual test: no crash, no hang. */
            crimp_squashfs_entry_list list;
            if (crimp_squashfs_list(WORK_FILE, &list) == 0) {
                crimp_squashfs_entry_list_free(&list);
            }

            crimp_squashfs_entry_list extract_list;
            if (crimp_squashfs_extract(WORK_FILE, OUTPUT_DIR, &extract_list) == 0) {
                crimp_squashfs_entry_list_free(&extract_list);
            }

            iterations++;
        }
    }

    free(mutated);
    free(original);

    printf("PASS: %ld single-byte mutations of %s survived crimp_squashfs_list + "
           "crimp_squashfs_extract without crashing\n",
           iterations, FIXTURE_PATH);
    return 0;
}
