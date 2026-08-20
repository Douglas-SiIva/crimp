#ifndef CRIMP_INVENTORY_H
#define CRIMP_INVENTORY_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Inventory data (what component/version is present) is distinct from a
 * detector's findings (what's wrong) — it feeds the SBOM generator and the
 * CVE-matching detector, it isn't itself a vulnerability. */
typedef struct {
    const char *component; /* e.g. "OpenSSL" — string literal, not owned */
    char version[64];      /* e.g. "1.1.1k"; empty if identified but version text didn't parse */
    char *path;            /* owned copy of the file the component was found in */
} crimp_component;

typedef struct {
    crimp_component *items;
    size_t count;
    size_t capacity;
} crimp_component_list;

void crimp_component_list_init(crimp_component_list *list);
void crimp_component_list_add(crimp_component_list *list, const char *component,
                               const char *version, const char *path);
void crimp_component_list_free(crimp_component_list *list);

/* Walks `root_path` looking for embedded version strings of common
 * firmware components (BusyBox, OpenSSL, Dropbear, Linux kernel). Scans
 * raw file content, not just text files — version strings often live
 * inside compiled binaries. */
void crimp_identify_components(const char *root_path, crimp_component_list *out);

#ifdef __cplusplus
}
#endif

#endif /* CRIMP_INVENTORY_H */
