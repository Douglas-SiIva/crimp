#ifndef CRIMP_DETECTORS_H
#define CRIMP_DETECTORS_H

#include "crimp/detector.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Built-in detectors. Each corresponds to a roadmap issue — see
 * CONTRIBUTING.md for how to add a new one. */
extern const crimp_detector crimp_detector_weak_credentials;
extern const crimp_detector crimp_detector_exposed_protocols;
extern const crimp_detector crimp_detector_weak_crypto;

#ifdef __cplusplus
}
#endif

#endif /* CRIMP_DETECTORS_H */
