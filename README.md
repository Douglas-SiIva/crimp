# Crimp

[![CI](https://github.com/Douglas-SiIva/crimp/actions/workflows/ci.yml/badge.svg)](https://github.com/Douglas-SiIva/crimp/actions/workflows/ci.yml)
[![Quality gate status](https://sonarcloud.io/api/project_badges/measure?project=Douglas-SiIva_crimp&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=Douglas-SiIva_crimp)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Open source firmware and IoT security scanner. Detects weak/hardcoded credentials, outdated components with known CVEs, exposed protocols (unauthenticated MQTT/CoAP/UPnP/mDNS, open debug ports), weak cryptography, and generates SBOMs in CycloneDX format.

Written in C/C++. Built with CMake and [vcpkg](https://vcpkg.io) for dependency management.

## Status

Early development. Not ready for use yet.

## Building

```sh
git clone --recurse-submodules https://github.com/Douglas-SiIva/crimp.git
cd crimp
./vcpkg/bootstrap-vcpkg.sh   # or bootstrap-vcpkg.bat on Windows
cmake --preset default
cmake --build build
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache License 2.0](LICENSE).
