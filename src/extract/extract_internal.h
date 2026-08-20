#ifndef CRIMP_EXTRACT_INTERNAL_H
#define CRIMP_EXTRACT_INTERNAL_H

#include "crimp/extract.h"

int crimp_squashfs_identify(const char *path, crimp_fs_info *out);
const char *crimp_squashfs_compression_name(uint16_t id);

#endif /* CRIMP_EXTRACT_INTERNAL_H */
