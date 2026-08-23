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

static void scan_directory(const char *root_path) {
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
                "%s: extraction failed (malformed image or unsupported compressor)\n", path);
        return;
    }

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
