#include "crimp/extract.h"

#include <stdio.h>
#include <string.h>

#ifndef FIXTURE_WITH_BIGFILE
#error "FIXTURE_WITH_BIGFILE must be defined by the build (see CMakeLists.txt)"
#endif
#ifndef FIXTURE_WITHOUT_BIGFILE
#error "FIXTURE_WITHOUT_BIGFILE must be defined by the build (see CMakeLists.txt)"
#endif

/* Regression coverage for crimp_fs_extract()'s "extract to a fresh temp dir,
 * only replace output_dir once extraction fully succeeds" contract - added
 * after /code-review found two real bugs in an earlier version that wrote
 * directly into output_dir: (1) a failed extraction could still mutate/taint
 * a prior *good* output_dir even when nothing about this run ever touched
 * it, and (2) a successful re-extraction into a reused output_dir left stale
 * files from the previous image behind instead of fully replacing the tree.
 * Both are exercised below against real fixtures, not synthetic ones. */

static int file_exists(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f) {
        fclose(f);
        return 1;
    }
    return 0;
}

static int read_file(const char *path, char *buf, size_t cap) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        return -1;
    }
    size_t n = fread(buf, 1, cap - 1, f);
    fclose(f);
    buf[n] = '\0';
    return 0;
}

int main(void) {
    const char *output_dir = "fs_extract_test_output";
    char bigfile_path[512];
    char passwd_path[512];
    snprintf(bigfile_path, sizeof(bigfile_path), "%s/bin/bigfile.bin", output_dir);
    snprintf(passwd_path, sizeof(passwd_path), "%s/etc/passwd", output_dir);

    /* 1. First extraction: FIXTURE_WITH_BIGFILE has bin/bigfile.bin. */
    if (crimp_fs_extract(FIXTURE_WITH_BIGFILE, output_dir) != 0) {
        fprintf(stderr, "FAIL: expected extraction of %s to succeed\n", FIXTURE_WITH_BIGFILE);
        return 1;
    }
    if (!file_exists(bigfile_path)) {
        fprintf(stderr, "FAIL: expected %s to exist after the first extraction\n", bigfile_path);
        return 1;
    }

    /* 2. Re-extract a DIFFERENT tree (no bin/bigfile.bin) into the SAME
     * output_dir - the old file must be gone afterward, not left behind
     * alongside the new tree (a full replace, not a merge). */
    if (crimp_fs_extract(FIXTURE_WITHOUT_BIGFILE, output_dir) != 0) {
        fprintf(stderr, "FAIL: expected re-extraction of %s to succeed\n",
                FIXTURE_WITHOUT_BIGFILE);
        return 1;
    }
    if (file_exists(bigfile_path)) {
        fprintf(stderr,
                "FAIL: '%s' from the first extraction should not survive a successful "
                "re-extraction of a different image into the same output_dir\n",
                bigfile_path);
        return 1;
    }
    char passwd_content[256];
    if (read_file(passwd_path, passwd_content, sizeof(passwd_content)) != 0) {
        fprintf(stderr, "FAIL: expected '%s' to exist after the second extraction\n",
                passwd_path);
        return 1;
    }

    /* 3. A malformed (non-squashfs) image extracted into a FRESH output_dir
     * that never existed before must fail and leave nothing behind at all. */
    const char *bad_path = "test_fixture_fs_extract_not_squashfs.bin";
    FILE *bf = fopen(bad_path, "wb");
    if (!bf) {
        fprintf(stderr, "FAIL: could not create %s\n", bad_path);
        return 1;
    }
    char junk[128];
    memset(junk, 0, sizeof(junk));
    fwrite(junk, 1, sizeof(junk), bf);
    fclose(bf);

    const char *fresh_output_dir = "fs_extract_test_output_fresh";
    if (crimp_fs_extract(bad_path, fresh_output_dir) == 0) {
        fprintf(stderr, "FAIL: expected extraction of a non-squashfs file to fail\n");
        return 1;
    }
    if (file_exists(fresh_output_dir)) {
        fprintf(stderr,
                "FAIL: '%s' should not exist at all after a failed extraction that never had "
                "anything to replace\n",
                fresh_output_dir);
        return 1;
    }

    /* 4. The critical regression: a failed extraction attempt into an
     * output_dir that already holds a GOOD prior extraction (from step 2)
     * must leave that prior content completely untouched, not tainted or
     * partially overwritten. */
    if (crimp_fs_extract(bad_path, output_dir) == 0) {
        fprintf(stderr, "FAIL: expected extraction of a non-squashfs file to fail\n");
        return 1;
    }
    char passwd_content_after[256];
    if (read_file(passwd_path, passwd_content_after, sizeof(passwd_content_after)) != 0) {
        fprintf(stderr,
                "FAIL: '%s' from the prior good extraction should still exist after a failed "
                "re-extraction attempt\n",
                passwd_path);
        return 1;
    }
    if (strcmp(passwd_content, passwd_content_after) != 0) {
        fprintf(stderr,
                "FAIL: '%s' content changed after a failed re-extraction attempt - the prior "
                "good extraction was corrupted\n",
                passwd_path);
        return 1;
    }

    printf("PASS: crimp_fs_extract replaces output_dir atomically and never taints a prior "
           "good extraction on failure\n");
    return 0;
}
