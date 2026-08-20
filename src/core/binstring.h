#ifndef CRIMP_CORE_BINSTRING_H
#define CRIMP_CORE_BINSTRING_H

#include <stddef.h>

/* Like strstr(), but safe for buffers that may contain embedded NUL bytes
 * (e.g. raw binary/executable content) — strstr() would stop at the first
 * NUL, which is wrong for scanning a binary blob rather than a C string.
 * Returns a pointer into `haystack`, or NULL if `needle` isn't found. */
const char *crimp_memfind(const char *haystack, size_t haystack_len, const char *needle);

#endif /* CRIMP_CORE_BINSTRING_H */
