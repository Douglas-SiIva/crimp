#ifndef CRIMP_FS_UTIL_H
#define CRIMP_FS_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* Filesystem-parsing helpers shared by every extractor in src/extract/
 * (squashfs.c, cramfs.c, ...) - path safety, directory/symlink containment,
 * and a portable 64-bit seek. Originally squashfs-only; factored out once
 * cramfs needed the identical logic rather than a second copy. */

/* fseek() takes a `long` offset, which is only 32 bits under the LLP64
 * model MinGW targets on Windows (this project's documented Windows build)
 * - casting a 64-bit table offset into that truncates silently for offsets
 * past ~2GB. Use the platform's real 64-bit seek. */
int crimp_fs_seek64(FILE *f, uint64_t offset);

/* A directory entry name is untrusted. Rejects anything that could turn
 * "output_dir + name" into a path escaping output_dir once joined (".",
 * "..", any embedded path separator - both "/" and "\\", since a name
 * crafted on one platform must not escape when Crimp runs on the other -
 * or drive-letter colon), anything that would silently truncate once
 * C-string functions touch it (an embedded NUL byte), or a Windows-reserved
 * device name. A real, non-adversarial image never produces any of these,
 * so this can't reject legitimate images - only crafted (or, for the
 * device-name case, merely unlucky) ones. */
int crimp_fs_path_component_is_safe(const char *name, size_t len);

/* Returns 1 if `path` exists and is *itself* a real directory, 0 otherwise
 * (including on stat failure or if it's a symlink/junction - deliberately
 * not followed, even one pointing at a real directory). */
int crimp_fs_path_is_existing_directory(const char *path);

/* Returns 1 if `path` already exists and is a symlink (POSIX) or reparse
 * point (Windows - junctions and symlinks both set this flag), 0 otherwise.
 * Never follows the link to check what it points to. */
int crimp_fs_path_is_symlink(const char *path);

/* mkdir() reporting EEXIST only means *something* is already there - not
 * necessarily a directory. Verifies that before treating it as success. */
int crimp_fs_make_directory(const char *path);

/* Joins output_dir and rel_path, rejecting (rather than silently
 * truncating) anything that doesn't fit - a truncated path could resolve
 * to somewhere unintended just as easily as a traversal could. */
int crimp_fs_join_output_path(const char *output_dir, const char *rel_path, char *out,
                               size_t out_cap);

#endif /* CRIMP_FS_UTIL_H */
