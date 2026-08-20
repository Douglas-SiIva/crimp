#ifndef CRIMP_CORE_WALK_H
#define CRIMP_CORE_WALK_H

typedef void (*crimp_file_visitor)(const char *path, void *userdata);

/* Recursively visits every regular file under `dir_path`, calling `visit`
 * for each one. Silently does nothing if `dir_path` can't be opened. */
void crimp_walk_directory(const char *dir_path, crimp_file_visitor visit, void *userdata);

#endif /* CRIMP_CORE_WALK_H */
