#ifndef CRIMP_SBOM_H
#define CRIMP_SBOM_H

#include <stdio.h>

#include "crimp/inventory.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Writes a CycloneDX 1.6 SBOM (JSON) listing `components` to `out`. Each
 * component's discovery location is recorded as a CycloneDX
 * evidence.occurrences entry. */
void crimp_sbom_write_cyclonedx(const crimp_component_list *components, FILE *out);

#ifdef __cplusplus
}
#endif

#endif /* CRIMP_SBOM_H */
