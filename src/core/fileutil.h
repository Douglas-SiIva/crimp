#ifndef CRIMP_CORE_FILEUTIL_H
#define CRIMP_CORE_FILEUTIL_H

#include <stddef.h>

/* Reads up to buf_size - 1 bytes of `path` into `buf`, NUL-terminating the
 * result. Returns the number of bytes read, or -1 if the file couldn't be
 * opened. Intended for text-pattern scanning of small-to-medium config
 * files, not for reading arbitrary binary data. */
long crimp_read_file_chunk(const char *path, char *buf, size_t buf_size);

#endif /* CRIMP_CORE_FILEUTIL_H */
