#ifndef CRIMP_EXTRACT_H
#define CRIMP_EXTRACT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CRIMP_FS_UNKNOWN = 0,
    CRIMP_FS_SQUASHFS,
    CRIMP_FS_CRAMFS,
    CRIMP_FS_JFFS2,
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

/* Extracts the recognized filesystem at `path` into `output_dir` (created if
 * missing), mirroring its directory structure with real (decompressed) file
 * content, so detectors/SBOM generation can run against it directly. Returns
 * 0 on success, -1 if the format isn't recognized/supported (including an
 * unsupported compressor) or extraction otherwise failed (malformed image,
 * output_dir couldn't be created/written to). */
int crimp_fs_extract(const char *path, const char *output_dir);

#ifdef __cplusplus
}
#endif

#endif /* CRIMP_EXTRACT_H */
