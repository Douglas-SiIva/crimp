#ifndef CRIMP_EXTRACT_H
#define CRIMP_EXTRACT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CRIMP_FS_UNKNOWN = 0,
    CRIMP_FS_SQUASHFS,
} crimp_fs_type;

typedef struct {
    crimp_fs_type type;
    uint32_t inode_count;
    uint32_t block_size;
    uint16_t compression; /* filesystem-specific id; see crimp_fs_compression_name() */
    uint64_t bytes_used;
} crimp_fs_info;

/* Identifies the filesystem at `path` and fills `out` with metadata parsed
 * from its superblock/header. Returns 0 on success, -1 if the file could
 * not be read or the format is not recognized. */
int crimp_fs_identify(const char *path, crimp_fs_info *out);

const char *crimp_fs_compression_name(crimp_fs_type type, uint16_t compression);

#ifdef __cplusplus
}
#endif

#endif /* CRIMP_EXTRACT_H */
