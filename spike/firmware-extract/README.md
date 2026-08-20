Spike for risk #1 (real firmware extraction in C/C++) — **validated, superseded by real code**.

The SquashFS superblock parser that lived here has been moved into
`src/extract/squashfs.c` behind the public `crimp_fs_identify()` API
(`include/crimp/extract.h`). Full extraction (inode/directory tables, block
decompression) is tracked as its own issue (#7), not part of this spike.

To get a real firmware sample for testing:

```sh
curl -sL "https://downloads.openwrt.org/releases/23.05.5/targets/x86/64/openwrt-23.05.5-x86-64-generic-squashfs-rootfs.img.gz" -o samples/rootfs.img.gz
gunzip samples/rootfs.img.gz
```

```sh
./build/crimp samples/rootfs.img
```
