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
