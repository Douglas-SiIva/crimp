#ifndef CRIMP_EXTRACT_INTERNAL_H
#define CRIMP_EXTRACT_INTERNAL_H

#include "crimp/extract.h"

#include <stddef.h>

int crimp_squashfs_identify(const char *path, crimp_fs_info *out);
const char *crimp_squashfs_compression_name(uint16_t id);

/* Issue #7 milestone 1: walks the inode + directory tables to list every
 * entry (path, type, uncompressed size) without extracting file content —
 * only supports images whose metadata blocks are stored uncompressed
 * (milestone 2 adds real decompression, starting with gzip). See
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

#endif /* CRIMP_EXTRACT_INTERNAL_H */
