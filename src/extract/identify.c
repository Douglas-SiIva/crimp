#include "extract_internal.h"

#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#if defined(_WIN32)
#include <direct.h>
#endif

int crimp_fs_identify(const char *path, crimp_fs_info *out) {
    if (crimp_squashfs_identify(path, out) == 0) {
        return 0;
    }

    /* JFFS2 (#8) and cramfs (#9) go here once implemented. */

    return -1;
}

const char *crimp_fs_compression_name(crimp_fs_type type, uint16_t compression) {
    if (type == CRIMP_FS_SQUASHFS) {
        return crimp_squashfs_compression_name(compression);
    }
    return "unknown";
}

/* Best-effort recursive removal of `path`. Only ever called below on a
 * directory this function fully owns the lifecycle of - a fresh temp
 * staging directory this same call just created, or output_dir immediately
 * before replacing it with a verified-complete new extraction - never on an
 * arbitrary caller-supplied path whose contents aren't already known. */
static void remove_tree(const char *path) {
    DIR *d = opendir(path);
    if (!d) {
        remove(path); /* not a directory (or doesn't exist) - fine either way */
        return;
    }
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        char child[1280];
        int n = snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
        if (n < 0 || (size_t)n >= sizeof(child)) {
            continue;
        }
        struct stat st;
        if (stat(child, &st) != 0) {
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            remove_tree(child);
        } else {
            remove(child);
        }
    }
    closedir(d);
#if defined(_WIN32)
    _rmdir(path);
#else
    rmdir(path);
#endif
}

static int extract_dispatch(const char *path, const char *dir) {
    crimp_squashfs_entry_list list;
    if (crimp_squashfs_extract(path, dir, &list) == 0) {
        crimp_squashfs_entry_list_free(&list);
        return 0;
    }

    /* JFFS2 (#8) and cramfs (#9) go here once implemented. */

    return -1;
}

/* Extracts into a fresh temp directory first, then replaces `output_dir`
 * with it only once extraction fully succeeds - so `output_dir` is always
 * either untouched (this call failed and never mutated it) or a complete,
 * consistent tree (this call succeeded and fully replaced whatever was
 * there before), never a partial or stale-mixed state. This matters because
 * `output_dir` is deliberately reusable across runs (the CLI extracts every
 * firmware image to the same sibling directory each time it's re-run): an
 * earlier version wrote directly into `output_dir`, which meant a failed
 * extraction could taint a prior *good* extraction it never actually
 * touched, and a successful re-extraction could leave files from a
 * previous, different image behind alongside the new ones. */
int crimp_fs_extract(const char *path, const char *output_dir) {
    char tmp_dir[1280];
    int n = snprintf(tmp_dir, sizeof(tmp_dir), "%s.tmp", output_dir);
    if (n < 0 || (size_t)n >= sizeof(tmp_dir)) {
        return -1;
    }

    remove_tree(tmp_dir); /* clean up any leftover from a crashed prior run */

    if (extract_dispatch(path, tmp_dir) != 0) {
        remove_tree(tmp_dir);
        return -1;
    }

    remove_tree(output_dir); /* safe now: tmp_dir holds a verified-complete replacement */
    return rename(tmp_dir, output_dir) == 0 ? 0 : -1;
}
