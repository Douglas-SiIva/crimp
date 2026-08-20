Spike for risk #1: can we read real firmware filesystem structures in C/C++
without a third-party SquashFS library?

`parse_squashfs_superblock.c` parses the 96-byte SquashFS 4.0 superblock
directly and validates the result against a real firmware image.

To reproduce, download a real SquashFS rootfs image (not committed — too
large for git):

```sh
curl -sL "https://downloads.openwrt.org/releases/23.05.5/targets/x86/64/openwrt-23.05.5-x86-64-generic-squashfs-rootfs.img.gz" -o samples/rootfs.img.gz
gunzip samples/rootfs.img.gz
```

Then build and run:

```sh
gcc parse_squashfs_superblock.c -o parse_squashfs_superblock
./parse_squashfs_superblock samples/rootfs.img
```

Output matched `file`'s independent identification of the same image
exactly (inode count, block size, compression, bytes used) — confirming the
format is straightforward enough to parse without vendoring libsqsh or
similar. Full extraction (inode table, directory table, block
decompression) is the next incremental step, not an open unknown.
