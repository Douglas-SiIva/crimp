# Test fixtures

## squashfs_uncompressed.img

A minimal SquashFS 4.0 image with all block/table compression disabled
(`mksquashfs ... -noI -noD -noF -noX`), so it exercises `crimp_squashfs_list`
without needing a decompressor (issue #7 milestone 1 — see
`.claude/skills/squashfs-extraction/SKILL.md`). Committed as a binary fixture
rather than generated at test time because `mksquashfs` isn't installed on
the CI runners or guaranteed to be available locally.

Regenerate with (on any machine with `squashfs-tools` installed — on
Windows, easiest via WSL):

```sh
mkdir -p /tmp/crimp_fixture/root/etc /tmp/crimp_fixture/root/bin/nested
echo "hello=world" > /tmp/crimp_fixture/root/etc/config.txt
echo "root:x:0:0:root:/root:/bin/sh" > /tmp/crimp_fixture/root/etc/passwd
printf "FAKE_BUSYBOX_BINARY_CONTENT_1234567890" > /tmp/crimp_fixture/root/bin/busybox
printf "nested file content here" > /tmp/crimp_fixture/root/bin/nested/deep.txt
ln -s /bin/busybox /tmp/crimp_fixture/root/bin/sh
mksquashfs /tmp/crimp_fixture/root squashfs_uncompressed.img -noI -noD -noF -noX -all-root -no-progress
```

Expected listing (validated against `unsquashfs -l` when this fixture was
generated):

```
bin/            (dir)
bin/busybox     (file, 38 bytes)
bin/nested/     (dir)
bin/nested/deep.txt (file, 24 bytes)
bin/sh          (file/symlink, 12 bytes — target "/bin/busybox")
etc/            (dir)
etc/config.txt  (file, 12 bytes)
etc/passwd      (file, 30 bytes)
```

## squashfs_gzip.img

Same tree as `squashfs_uncompressed.img` above, but genuinely gzip-compressed
(`mksquashfs -comp gzip`, no `-noI -noD -noF -noX`) — exercises real
decompression (issue #7 milestone 2) rather than the uncompressed fast path.
Same expected listing as above. Regenerate with:

```sh
mkdir -p /tmp/crimp_fixture/root/etc /tmp/crimp_fixture/root/bin/nested
echo "hello=world" > /tmp/crimp_fixture/root/etc/config.txt
echo "root:x:0:0:root:/root:/bin/sh" > /tmp/crimp_fixture/root/etc/passwd
printf "FAKE_BUSYBOX_BINARY_CONTENT_1234567890" > /tmp/crimp_fixture/root/bin/busybox
printf "nested file content here" > /tmp/crimp_fixture/root/bin/nested/deep.txt
ln -s /bin/busybox /tmp/crimp_fixture/root/bin/sh
mksquashfs /tmp/crimp_fixture/root squashfs_gzip.img -comp gzip -all-root -no-progress
```

Before landing full gzip support, this same tree was cross-checked against a
much larger, real-world image: a gzip-compressed SquashFS built from a real
`/usr/share/doc` tree (~3370 entries, spanning multiple 8KiB metadata
blocks), diffed path-for-path and size-for-size against `unsquashfs -l` and
the real filesystem — exact match. That large image isn't committed (too
big for a fixture); regenerate it ad hoc with `mksquashfs /usr/share/doc
large.img -comp gzip -all-root` if you need to re-verify against something
bigger than this toy tree.

## squashfs_extract.img

Same tree/content as `squashfs_gzip.img`, but `bin/bigfile.bin` is a
deterministic 11000-byte repeating `"0123456789"` pattern and the image is
built with a small 4KiB block size (`-b 4096`) instead of the default
128KiB — deliberately small so a single file spans two full data blocks
plus a fragment-packed tail, exercising `block_sizes[]` parsing and the
fragment table lookup (issue #7 milestone 2b, `crimp_squashfs_extract`)
rather than just the single-fragment case every other fixture here hits.
Regenerate with:

```sh
mkdir -p /tmp/crimp_fixture/etc /tmp/crimp_fixture/bin/nested
echo "hello=world" > /tmp/crimp_fixture/etc/config.txt
echo "root:x:0:0:root:/root:/bin/sh" > /tmp/crimp_fixture/etc/passwd
printf "FAKE_BUSYBOX_BINARY_CONTENT_1234567890" > /tmp/crimp_fixture/bin/busybox
printf "nested file content here" > /tmp/crimp_fixture/bin/nested/deep.txt
ln -s /bin/busybox /tmp/crimp_fixture/bin/sh
python3 -c "import sys; sys.stdout.buffer.write((b'0123456789' * 1100)[:11000])" \
    > /tmp/crimp_fixture/bin/bigfile.bin
mksquashfs /tmp/crimp_fixture squashfs_extract.img -comp gzip -b 4096 -all-root -no-progress
```

Validated three ways before landing: (1) content of every extracted regular
file byte-for-byte identical to `unsquashfs -d`'s output (sha256sum match,
including the multi-block+fragment `bigfile.bin`); (2) a separate, larger
ad hoc image (a real 300KB file, default 128KiB block size, forcing 3 full
blocks + a fragment) cross-checked the same way; (3) a 600-unique-file ad
hoc image forcing 600 distinct fragment table entries (over the
512-per-metadata-block threshold, so the fragment table's own two-level
indirection - not just the already-covered inode/directory table one - got
exercised for the first time), all 600 extracted files byte-for-byte
matching `unsquashfs -d`. Neither larger image is committed (too big for a
fixture); regenerate ad hoc if you need to re-verify against something
bigger than this toy tree. `bin/sh` (a symlink) is deliberately *not*
extracted as a file — milestone 2b only extracts regular file content.
