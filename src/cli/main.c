#include "crimp/extract.h"
#include "crimp/scan.h"
#include "crimp/sbom.h"

#include <stdio.h>
#include <string.h>
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

static void scan_directory(const char *root_path, const char *rules_dir) {
    crimp_scan_result result;
    crimp_scan_result_init(&result);
    if (crimp_scan_directory(root_path, rules_dir, &result) != 0) {
        fprintf(stderr, "warning: --rules directory '%s' could not be opened - no user-defined rules were loaded\n",
                rules_dir);
    }

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

static const char *fs_type_name(crimp_fs_type type) {
    switch (type) {
        case CRIMP_FS_SQUASHFS:
            return "squashfs";
        case CRIMP_FS_CRAMFS:
            return "cramfs";
        default:
            return "unknown";
    }
}

static void identify_and_extract(const char *path, const char *rules_dir) {
    crimp_fs_info info;
    if (crimp_fs_identify(path, &info) != 0) {
        fprintf(stderr, "%s: filesystem not recognized\n", path);
        return;
    }

    printf("filesystem:    %s\n", fs_type_name(info.type));
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
                "%s: extraction failed (malformed image or unsupported compressor)\n", path);
        return;
    }

    printf("Extraction complete, scanning...\n\n");
    scan_directory(output_dir, rules_dir);
}

int main(int argc, char **argv) {
    const char *target = NULL;
    const char *rules_dir = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--rules") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "%s: --rules requires a directory argument\n", argv[0]);
                return 1;
            }
            rules_dir = argv[++i];
        } else if (target == NULL) {
            target = argv[i];
        } else {
            target = NULL; /* more than one positional argument: usage error below */
            break;
        }
    }

    if (target == NULL) {
        fprintf(stderr, "usage: %s <firmware-image-or-extracted-dir> [--rules <dir>]\n", argv[0]);
        return 1;
    }

    if (is_directory(target)) {
        scan_directory(target, rules_dir);
    } else {
        identify_and_extract(target, rules_dir);
    }

    return 0;
}
