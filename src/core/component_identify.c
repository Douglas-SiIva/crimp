#include "crimp/inventory.h"

#include "binstring.h"
#include "fileutil.h"
#include "walk.h"

#include <ctype.h>
#include <string.h>

#define READ_CHUNK 262144

typedef struct {
    const char *marker;
    const char *component_name;
    /* Whether a trailing lowercase-letter run (after the digit/./- prefix)
     * is kept as part of the version - see extract_version(). Opt-in per
     * marker, not global: OpenSSL's classic "1.1.1k"-style trailing patch
     * letter is a real, common case worth capturing, but the same
     * widening applied indiscriminately would swallow unrelated trailing
     * text into other components' reported versions (e.g. a kernel banner
     * like "Linux version 5.4.219-yocto-standard" - "-yocto-standard" is a
     * build tag, not part of the version). */
    int allow_letter_suffix;
} component_marker;

static const component_marker COMPONENT_MARKERS[] = {
    {"BusyBox v", "BusyBox", 0},
    {"OpenSSL ", "OpenSSL", 1},
    {"dropbear_", "Dropbear", 0},
    {"Linux version ", "Linux kernel", 0},
};
#define COMPONENT_MARKER_COUNT (sizeof(COMPONENT_MARKERS) / sizeof(COMPONENT_MARKERS[0]))

/* Copies leading version-shaped characters (digits, '.', '-', and -
 * only when `allow_letter_suffix` is set - lowercase letters) from `start`
 * into `out`, stopping at the first character that doesn't fit, at
 * `max_len` bytes remaining in the source buffer, or at an embedded NUL
 * (binary data, not a printable version string here). See
 * component_marker.allow_letter_suffix for why this is opt-in rather than
 * a blanket widening - a real "1.1.1n" install extracted as just "1.1.1"
 * compares as *older* than any lettered version and over-reports CVEs
 * actually fixed by that patch letter (see crimp/cve.h's version-accuracy
 * note), but only OpenSSL's own version scheme actually needs this. */
static void extract_version(const char *start, size_t max_len, char *out, size_t out_size,
                             int allow_letter_suffix) {
    size_t i = 0;
    while (i < out_size - 1 && i < max_len && start[i] != '\0' &&
           (isdigit((unsigned char)start[i]) || start[i] == '.' || start[i] == '-' ||
            (allow_letter_suffix && start[i] >= 'a' && start[i] <= 'z'))) {
        out[i] = start[i];
        i++;
    }
    out[i] = '\0';
}

static void scan_file(const char *path, void *userdata) {
    crimp_component_list *out = (crimp_component_list *)userdata;

    char buf[READ_CHUNK];
    long n = crimp_read_file_chunk(path, buf, sizeof(buf));
    if (n <= 0) {
        return;
    }

    for (size_t i = 0; i < COMPONENT_MARKER_COUNT; i++) {
        const char *marker = COMPONENT_MARKERS[i].marker;
        const char *found = crimp_memfind(buf, (size_t)n, marker);
        if (!found) {
            continue;
        }

        const char *version_start = found + strlen(marker);
        size_t remaining = (size_t)n - (size_t)(version_start - buf);

        char version[64];
        extract_version(version_start, remaining, version, sizeof(version),
                          COMPONENT_MARKERS[i].allow_letter_suffix);

        crimp_component_list_add(out, COMPONENT_MARKERS[i].component_name, version, path);
    }
}

void crimp_identify_components(const char *root_path, crimp_component_list *out) {
    crimp_walk_directory(root_path, scan_file, out);
}
