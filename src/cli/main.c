#include "crimp/extract.h"
#include "crimp/scan.h"
#include "crimp/sbom.h"

#include <stdio.h>
#include <sys/stat.h>

static const char *severity_name(crimp_severity s) {
    switch (s) {
        case CRIMP_SEVERITY_LOW:
            return "LOW";
        case CRIMP_SEVERITY_MEDIUM:
            return "MEDIUM";
        case CRIMP_SEVERITY_HIGH:
            return "HIGH";
        case CRIMP_SEVERITY_CRITICAL:
            return "CRITICAL";
        default:
            return "UNKNOWN";
    }
}

static int is_directory(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        return 0;
    }
    return S_ISDIR(st.st_mode) ? 1 : 0;
}

/* A failed crimp_fs_extract() call can still leave a partial tree on disk
 * (files from before the failing block/entry, per-file cleanup already
 * removes a truncated file but not everything extracted before it) - and
 * output_dir is deliberately reusable across runs (crimp_squashfs_extract's
 * make_directory() tolerates an already-existing directory on purpose), so
 * blindly deleting it on failure would risk destroying a prior *successful*
 * extraction the user is intentionally re-using. Instead, drop a marker file
 * a later `crimp <dir>` invocation checks for and refuses to scan, so a
 * known-incomplete tree can never silently produce a report that looks
 * complete. */
#define INCOMPLETE_MARKER_NAME ".crimp-extraction-incomplete"

static int build_marker_path(const char *root_path, char *out, size_t out_cap) {
    int n = snprintf(out, out_cap, "%s/%s", root_path, INCOMPLETE_MARKER_NAME);
    return (n < 0 || (size_t)n >= out_cap) ? -1 : 0;
}

static void mark_extraction_incomplete(const char *output_dir) {
    char marker_path[1280];
    if (build_marker_path(output_dir, marker_path, sizeof(marker_path)) != 0) {
        return;
    }
    FILE *f = fopen(marker_path, "wb");
    if (f) {
        fputs("This directory is the result of a FAILED crimp extraction and may be "
              "missing files or contain truncated content. Do not scan it as a complete "
              "firmware tree - re-run crimp on the original image instead.\n",
              f);
        fclose(f);
    }
}

/* Clears a marker left by a previous failed run reusing the same output_dir,
 * now that this run's extraction succeeded and the tree is complete again. */
static void clear_incomplete_marker(const char *output_dir) {
    char marker_path[1280];
    if (build_marker_path(output_dir, marker_path, sizeof(marker_path)) != 0) {
        return;
    }
    remove(marker_path);
}

static int extraction_is_marked_incomplete(const char *root_path) {
    char marker_path[1280];
    if (build_marker_path(root_path, marker_path, sizeof(marker_path)) != 0) {
        return 0;
    }
    FILE *f = fopen(marker_path, "rb");
    if (!f) {
        return 0;
    }
    fclose(f);
    return 1;
}

static void scan_directory(const char *root_path) {
    if (extraction_is_marked_incomplete(root_path)) {
        fprintf(stderr,
                "%s: marked as an incomplete extraction (a previous crimp run on the "
                "original firmware image failed partway through) - re-run crimp on the "
                "original image instead of scanning this directory\n",
                root_path);
        return;
    }

    crimp_scan_result result;
    crimp_scan_result_init(&result);
    crimp_scan_directory(root_path, &result);

    printf("=== Findings (%zu) ===\n", result.findings.count);
    for (size_t i = 0; i < result.findings.count; i++) {
        printf("[%s] %s: %s\n", severity_name(result.findings.items[i].severity),
               result.findings.items[i].detector_name, result.findings.items[i].description);
    }

    printf("\n=== Components identified (%zu) ===\n", result.components.count);
    for (size_t i = 0; i < result.components.count; i++) {
        printf("%s %s (%s)\n", result.components.items[i].component,
               result.components.items[i].version, result.components.items[i].path);
    }

    FILE *sbom_file = fopen("sbom.cdx.json", "wb");
    if (sbom_file) {
        crimp_sbom_write_cyclonedx(&result.components, sbom_file);
        fclose(sbom_file);
        printf("\nSBOM written to sbom.cdx.json\n");
    }

    crimp_scan_result_free(&result);
}

static void identify_and_extract(const char *path) {
    crimp_fs_info info;
    if (crimp_fs_identify(path, &info) != 0) {
        fprintf(stderr, "%s: filesystem not recognized\n", path);
        return;
    }

    printf("filesystem:    squashfs\n");
    printf("inodes:        %u\n", info.inode_count);
    printf("block_size:    %u\n", info.block_size);
    printf("compression:   %s\n", crimp_fs_compression_name(info.type, info.compression));
    printf("bytes_used:    %llu\n", (unsigned long long)info.bytes_used);

    char output_dir[1024];
    int n = snprintf(output_dir, sizeof(output_dir), "%s.crimp-extracted", path);
    if (n < 0 || (size_t)n >= sizeof(output_dir)) {
        fprintf(stderr, "%s: path too long to build an extraction directory\n", path);
        return;
    }

    printf("\nExtracting to %s ...\n", output_dir);
    if (crimp_fs_extract(path, output_dir) != 0) {
        fprintf(stderr,
                "%s: extraction failed (malformed image or unsupported compressor) - %s may "
                "contain a partial tree, marked as incomplete\n",
                path, output_dir);
        mark_extraction_incomplete(output_dir);
        return;
    }
    clear_incomplete_marker(output_dir);

    printf("Extraction complete, scanning...\n\n");
    scan_directory(output_dir);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <firmware-image-or-extracted-dir>\n", argv[0]);
        return 1;
    }

    if (is_directory(argv[1])) {
        scan_directory(argv[1]);
    } else {
        identify_and_extract(argv[1]);
    }

    return 0;
}
