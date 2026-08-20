#include "walk.h"

#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

void crimp_walk_directory(const char *dir_path, crimp_file_visitor visit, void *userdata) {
    DIR *d = opendir(dir_path);
    if (!d) {
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);

        struct stat st;
        if (stat(path, &st) != 0) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            crimp_walk_directory(path, visit, userdata);
        } else if (S_ISREG(st.st_mode)) {
            visit(path, userdata);
        }
    }

    closedir(d);
}
