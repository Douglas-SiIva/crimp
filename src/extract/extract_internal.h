#ifndef CRIMP_EXTRACT_INTERNAL_H
#define CRIMP_EXTRACT_INTERNAL_H

#include "crimp/extract.h"

#include <stddef.h>

int crimp_squashfs_identify(const char *path, crimp_fs_info *out);
const char *crimp_squashfs_compression_name(uint16_t id);

/* Issue #7 milestone 1: walks the inode + directory tables to list every
 * entry (path, type, uncompressed size) without extracting file content.
 * Metadata block decompression (gzip) landed in milestone 2a. See
 * .claude/skills/squashfs-extraction/SKILL.md. */
typedef struct {
    char *path; /* relative to the image root, e.g. "etc/passwd"; owned */
    int is_dir;
    uint64_t size; /* uncompressed size; 0 for directories */
} crimp_squashfs_entry;

typedef struct {
    crimp_squashfs_entry *items;
    size_t count;
    size_t capacity;
} crimp_squashfs_entry_list;

void crimp_squashfs_entry_list_init(crimp_squashfs_entry_list *list);
void crimp_squashfs_entry_list_free(crimp_squashfs_entry_list *list);

/* Returns 0 on success, -1 on a malformed image, an unsupported (compressed
 * metadata) image, or if `path` can't be read/isn't a SquashFS image. */
int crimp_squashfs_list(const char *path, crimp_squashfs_entry_list *out);

/* Issue #7 milestone 2b: extracts every regular file's real content under
 * `output_dir` (created if missing), mirroring the image's directory
 * structure, and fills `out` the same way crimp_squashfs_list does. Every
 * entry name is validated before being joined into a disk path, so a
 * crafted image cannot write outside output_dir. Returns 0 on success, -1
 * on a malformed/unsupported image or if output_dir can't be created. */
int crimp_squashfs_extract(const char *path, const char *output_dir,
                            crimp_squashfs_entry_list *out);

#endif /* CRIMP_EXTRACT_INTERNAL_H */
