#include "crimp/inventory.h"

#include "binstring.h"
#include "walk.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Component version markers can sit anywhere in a real firmware binary -
 * a 256KB read window (crimp_read_file_chunk's typical use) missed
 * BusyBox's version string sitting past that offset in a real device
 * image. Cap at 8MB instead: generous for the embedded binaries these
 * markers target (busybox/openssl/dropbear/kernel banners are all well
 * under this in practice), while still bounding memory for a
 * pathologically large file. */
#define COMPONENT_SCAN_MAX (8 * 1024 * 1024)

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
    /* Whether to fall back to find_isolated_dropbear_version() when no
     * occurrence of `marker` is directly followed by a parseable version.
     * Opt-in and Dropbear-specific (see that function) - the assumption
     * "version text directly follows the marker" simply doesn't hold for
     * Dropbear real-world binaries, where the version is stored as its
     * own pooled string constant, referenced only through a "%s" format
     * placeholder at the actual marker occurrences. */
    int dropbear_version_fallback;
} component_marker;

static const component_marker COMPONENT_MARKERS[] = {
    {"BusyBox v", "BusyBox", 0, 0},
    {"OpenSSL ", "OpenSSL", 1, 0},
    {"dropbear_", "Dropbear", 0, 1},
    {"Linux version ", "Linux kernel", 0, 0},
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

/* True if buf[0..len) is exactly Dropbear's own CalVer scheme: 4 digits,
 * '.', 1-3 digits (e.g. "2019.78") - nothing else in a firmware image is
 * likely to coincidentally match this shape as an isolated, NUL-delimited
 * token, so it's safe to trust without further positional context. */
static int looks_like_dropbear_version(const char *tok, size_t len) {
    if (len < 6 || len > 8) {
        return 0;
    }
    for (size_t i = 0; i < 4; i++) {
        if (!isdigit((unsigned char)tok[i])) {
            return 0;
        }
    }
    if (tok[4] != '.') {
        return 0;
    }
    for (size_t i = 5; i < len; i++) {
        if (!isdigit((unsigned char)tok[i])) {
            return 0;
        }
    }
    return 1;
}

/* Confirmed against a real device firmware binary (GL.iNet GL-MT300N-V2,
 * OpenWrt 19.07.7): Dropbear's version literal ("2019.78") is stored as
 * its own isolated, NUL-terminated string constant, string-pool-adjacent
 * to unrelated text like "Dropbear SSH client v%s ..." rather than
 * concatenated after any marker text crimp searches for - the actual
 * "dropbear_" marker occurrences in the binary are config-path/ident
 * strings ("dropbear_rsa_host_key", "SSH-2.0-dropbear") with the version
 * substituted at runtime via a "%s" placeholder, never present as literal
 * text in the compiled binary. Scans the whole buffer (not windowed
 * around a marker occurrence, since the pooled string's position relative
 * to any specific marker hit isn't reliable) for the first NUL-delimited
 * token matching Dropbear's version shape. Returns 1 and fills `out` on
 * success, 0 if nothing matched. */
static int find_isolated_dropbear_version(const char *buf, size_t n, char *out, size_t out_size) {
    size_t start = 0;
    for (size_t i = 0; i <= n; i++) {
        if (i == n || buf[i] == '\0') {
            size_t len = i - start;
            if (looks_like_dropbear_version(buf + start, len) && len < out_size) {
                memcpy(out, buf + start, len);
                out[len] = '\0';
                return 1;
            }
            start = i + 1;
        }
    }
    return 0;
}

/* Reads up to COMPONENT_SCAN_MAX bytes of `path` into a heap-allocated
 * buffer (the file may be larger than a stack buffer should comfortably
 * hold). Returns NULL on failure; on success, *out_len is the number of
 * bytes actually read and the caller owns the returned buffer. */
static char *read_file_for_scan(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        return NULL;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    long size = ftell(f);
    if (size < 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }

    size_t to_read = (size_t)size;
    if (to_read > COMPONENT_SCAN_MAX) {
        to_read = COMPONENT_SCAN_MAX;
    }
    if (to_read == 0) {
        fclose(f);
        return NULL;
    }

    char *buf = (char *)malloc(to_read);
    if (!buf) {
        fclose(f);
        return NULL;
    }

    size_t n = fread(buf, 1, to_read, f);
    fclose(f);
    if (n == 0) {
        free(buf);
        return NULL;
    }

    *out_len = n;
    return buf;
}

static void scan_file(const char *path, void *userdata) {
    crimp_component_list *out = (crimp_component_list *)userdata;

    size_t n = 0;
    char *buf = read_file_for_scan(path, &n);
    if (!buf) {
        return;
    }

    for (size_t i = 0; i < COMPONENT_MARKER_COUNT; i++) {
        const char *marker = COMPONENT_MARKERS[i].marker;
        size_t marker_len = strlen(marker);

        const char *search_start = buf;
        size_t search_len = n;
        char version[64] = "";
        int found_any = 0;
        int matched = 0;

        /* A marker can appear more than once in a binary before an
         * occurrence that happens to be directly followed by a parseable
         * version. Keep looking past occurrences that aren't instead of
         * giving up on the first hit. (This alone isn't enough for
         * Dropbear - see dropbear_version_fallback below - but it's a
         * real, independently useful improvement for markers that do
         * have their version directly adjacent at some occurrence.) */
        while (search_len > 0) {
            const char *found = crimp_memfind(search_start, search_len, marker);
            if (!found) {
                break;
            }
            found_any = 1;

            const char *version_start = found + marker_len;
            size_t remaining = (size_t)((buf + n) - version_start);
            extract_version(version_start, remaining, version, sizeof(version),
                              COMPONENT_MARKERS[i].allow_letter_suffix);
            if (version[0] != '\0') {
                matched = 1;
                break;
            }

            search_start = found + 1;
            search_len = (size_t)((buf + n) - search_start);
        }

        if (!matched && found_any && COMPONENT_MARKERS[i].dropbear_version_fallback) {
            matched = find_isolated_dropbear_version(buf, n, version, sizeof(version));
        }

        if (matched) {
            crimp_component_list_add(out, COMPONENT_MARKERS[i].component_name, version, path);
        } else if (found_any) {
            crimp_component_list_add(out, COMPONENT_MARKERS[i].component_name, "", path);
        }
    }

    free(buf);
}

void crimp_identify_components(const char *root_path, crimp_component_list *out) {
    crimp_walk_directory(root_path, scan_file, out);
}
