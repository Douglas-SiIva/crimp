# Crimp

Open source firmware and IoT security scanner. Detects weak/hardcoded credentials, outdated components with known CVEs, exposed protocols (unauthenticated MQTT/CoAP/UPnP/mDNS, open debug ports), weak cryptography, and generates SBOMs in CycloneDX format.

Written in C/C++. Built with CMake and [vcpkg](https://vcpkg.io) for dependency management.

## Status

Early development. Not ready for use yet.

## Building

```sh
git clone --recurse-submodules https://github.com/<org>/crimp.git
cd crimp
./vcpkg/bootstrap-vcpkg.sh   # or bootstrap-vcpkg.bat on Windows
cmake --preset default
cmake --build build
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache License 2.0](LICENSE).
