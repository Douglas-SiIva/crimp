#include "fs_util.h"

#include <errno.h>
#include <string.h>

#if defined(_WIN32)
#include <direct.h>
#include <windows.h>
#else
#include <sys/stat.h>
#endif

int crimp_fs_seek64(FILE *f, uint64_t offset) {
#if defined(_WIN32)
    return _fseeki64(f, (long long)offset, SEEK_SET);
#else
    return fseeko(f, (off_t)offset, SEEK_SET);
#endif
}

/* Windows reserves these as device names regardless of extension or case
 * ("con", "CON", "con.txt" are all the console device, not a creatable
 * file) - a real hazard here since this project's documented build target
 * is Windows/MinGW, and an image built on Linux (where these are ordinary
 * filenames) can carry one without anything else being wrong with it. */
static const char *const WINDOWS_RESERVED_NAMES[] = {
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5",
    "com6", "com7", "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5",
    "lpt6", "lpt7", "lpt8", "lpt9",
};
#define WINDOWS_RESERVED_NAME_COUNT \
    (sizeof(WINDOWS_RESERVED_NAMES) / sizeof(WINDOWS_RESERVED_NAMES[0]))

static int is_windows_reserved_name(const char *name, size_t len) {
    size_t base_len = 0;
    while (base_len < len && name[base_len] != '.') {
        base_len++;
    }
    if (base_len == 0 || base_len > 4) {
        return 0; /* every reserved name's base is 3-4 chars */
    }
    for (size_t r = 0; r < WINDOWS_RESERVED_NAME_COUNT; r++) {
        const char *reserved = WINDOWS_RESERVED_NAMES[r];
        if (strlen(reserved) != base_len) {
            continue;
        }
        int match = 1;
        for (size_t i = 0; i < base_len; i++) {
            char c = name[i];
            if (c >= 'A' && c <= 'Z') {
                c = (char)(c - 'A' + 'a');
            }
            if (c != reserved[i]) {
                match = 0;
                break;
            }
        }
        if (match) {
            return 1;
        }
    }
    return 0;
}

int crimp_fs_path_component_is_safe(const char *name, size_t len) {
    if (len == 1 && name[0] == '.') {
        return 0;
    }
    if (len == 2 && name[0] == '.' && name[1] == '.') {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        char c = name[i];
        if (c == '/' || c == '\\' || c == ':' || c == '\0') {
            return 0;
        }
    }
    if (is_windows_reserved_name(name, len)) {
        return 0;
    }
    return 1;
}

int crimp_fs_path_is_existing_directory(const char *path) {
#if defined(_WIN32)
    DWORD attrs = GetFileAttributesA(path);
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
           (attrs & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
#else
    struct stat st;
    return lstat(path, &st) == 0 && S_ISDIR(st.st_mode);
#endif
}

int crimp_fs_path_is_symlink(const char *path) {
#if defined(_WIN32)
    DWORD attrs = GetFileAttributesA(path);
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
#else
    struct stat st;
    return lstat(path, &st) == 0 && S_ISLNK(st.st_mode);
#endif
}

int crimp_fs_make_directory(const char *path) {
#if defined(_WIN32)
    if (_mkdir(path) == 0) {
        return 0;
    }
    return (errno == EEXIST && crimp_fs_path_is_existing_directory(path)) ? 0 : -1;
#else
    /* Owner-only: extracted firmware content can legitimately contain
     * secrets (private keys, credentials - the exact things this tool's
     * own detectors look for), so the extraction tree shouldn't be
     * world-readable by default. */
    if (mkdir(path, 0700) == 0) {
        return 0;
    }
    return (errno == EEXIST && crimp_fs_path_is_existing_directory(path)) ? 0 : -1;
#endif
}

int crimp_fs_join_output_path(const char *output_dir, const char *rel_path, char *out,
                               size_t out_cap) {
    int n = snprintf(out, out_cap, "%s/%s", output_dir, rel_path);
    if (n < 0 || (size_t)n >= out_cap) {
        return -1;
    }
    return 0;
}
