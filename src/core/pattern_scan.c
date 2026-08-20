#include "pattern_scan.h"

#include "fileutil.h"
#include "walk.h"

#include <stdio.h>
#include <string.h>

#define READ_CHUNK 65536

typedef struct {
    const char *detector_name;
    const crimp_pattern_marker *markers;
    size_t marker_count;
    crimp_finding_list *out;
} scan_context;

static void scan_file(const char *path, void *userdata) {
    scan_context *ctx = (scan_context *)userdata;

    char buf[READ_CHUNK];
    if (crimp_read_file_chunk(path, buf, sizeof(buf)) <= 0) {
        return;
    }

    char desc[1024];
    for (size_t i = 0; i < ctx->marker_count; i++) {
        if (strstr(buf, ctx->markers[i].pattern)) {
            snprintf(desc, sizeof(desc), "%s (%s)", ctx->markers[i].description, path);
            crimp_finding_list_add(ctx->out, ctx->detector_name, desc, ctx->markers[i].severity);
        }
    }
}

void crimp_scan_directory_for_patterns(const char *root_path, const char *detector_name,
                                        const crimp_pattern_marker *markers, size_t marker_count,
                                        crimp_finding_list *out) {
    scan_context ctx = {detector_name, markers, marker_count, out};
    crimp_walk_directory(root_path, scan_file, &ctx);
}
