#include "fileutil.h"

#include <stdio.h>

long crimp_read_file_chunk(const char *path, char *buf, size_t buf_size) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        return -1;
    }

    size_t n = fread(buf, 1, buf_size - 1, f);
    fclose(f);
    buf[n] = '\0';
    return (long)n;
}
