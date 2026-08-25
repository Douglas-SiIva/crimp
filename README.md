# Crimp

[![CI](https://github.com/Douglas-SiIva/crimp/actions/workflows/ci.yml/badge.svg)](https://github.com/Douglas-SiIva/crimp/actions/workflows/ci.yml)
[![Quality gate status](https://sonarcloud.io/api/project_badges/measure?project=Douglas-SiIva_crimp&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=Douglas-SiIva_crimp)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Open source firmware and IoT security scanner. Extracts firmware images, detects weak/hardcoded credentials, outdated components with known CVEs, exposed protocols (unauthenticated MQTT/CoAP/UPnP/mDNS, open debug ports), weak cryptography, and generates SBOMs in CycloneDX 1.6 format.

Written in C/C++. Built with CMake and [vcpkg](https://vcpkg.io) for dependency management.

## Status

Early, but working end to end: point Crimp at a raw firmware image and it extracts the filesystem, runs its detectors, matches identified components against a local CVE dataset, and writes an SBOM. No tagged releases yet — expect breaking changes.

- **Filesystem extraction**: SquashFS (gzip/xz), cramfs, JFFS2 (big- and little-endian)
- **Detectors**: weak/hardcoded credentials, exposed protocols, weak cryptography, plus user-defined rules via YAML (`--rules`)
- **Component + CVE matching**: identifies BusyBox/OpenSSL/Dropbear/Linux kernel versions and matches them against a local, offline-synced CVE dataset (`--cve-dataset`) — no external API calls during a scan
- **SBOM**: CycloneDX 1.6, written on every scan

## Building

```sh
git clone --recurse-submodules https://github.com/Douglas-SiIva/crimp.git
cd crimp
./vcpkg/bootstrap-vcpkg.sh   # or bootstrap-vcpkg.bat on Windows
cmake --preset default
cmake --build build
```

## Usage

```sh
crimp <firmware-image-or-extracted-dir> [--rules <dir>] [--cve-dataset <file>]
```

`<firmware-image-or-extracted-dir>` can be a raw firmware image (extracted automatically) or an already-extracted directory. `--rules <dir>` loads custom YAML detector rules; `--cve-dataset <file>` matches identified components against a local CVE dataset — see [`data/cve_dataset.yaml`](data/cve_dataset.yaml) and [`scripts/sync_cve_dataset.py`](scripts/sync_cve_dataset.py) for the format and how it's synced from the NVD.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache License 2.0](LICENSE).
