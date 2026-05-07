# zipy

zipy is a small, fast ZIP extractor and C library. It reads ZIP central
directories, extracts stored and deflated entries, validates CRC32, restores
common Unix metadata, and keeps existing files safe on conflicts.

## Build

```sh
git submodule update --init
cmake -S . -B build
cmake --build build
```

The build creates `libzipy.a` and the `zipy` command line tool.

## Usage

```sh
zipy archive.zip -d target
zipy archive.zip -d target --fast
zipy archive.zip -d target -j auto
zipy archive.zip -d target -j cpu
zipy archive.zip -d target -j 1
zipy archive.zip -d target -p password
zipy archive.zip -d target --no-crc
zipy archive.zip -d target --no-metadata
zipy archive.zip -d target --atomic
zipy archive.zip -d target --resume
zipy archive.zip -d target --no-progress
```

`-j auto` is the default. It keeps small archives serial and uses CPU workers
when compressed, encrypted, or large stored workloads are big enough. `-j cpu`
forces one worker per CPU core, capped by the number of entries. Use an
explicit number such as `-j 4` to limit worker fan-out.

By default, the CLI asks what to do when an extracted entry would replace an
existing file. Non-interactive runs fall back to saving existing files before
writing new files.

With default conflict handling, when the target folder is empty or does not
exist yet, the CLI checks available disk space against the archive's
uncompressed size before extraction starts.

## Conflicts

```ini
on_conflict = ask | save | overwrite | skip | fail
save_to = target | home | trash
```

CLI defaults:

```ini
on_conflict = ask
save_to = target
```

Library defaults:

```ini
on_conflict = save
save_to = target
```

When `on_conflict = save`, existing files are moved into a generated saved
folder before extraction:

```text
target/
  zipy 2026-05-06 21-34-10 saved/
    zipy_saved_original_paths.txt
```

If the saved folder name already exists, zipy appends a number such as
`zipy 2026-05-06 21-34-10 saved 2`.

`save_to = target` creates the saved folder under the extraction target.
`save_to = home` creates it directly under `~/`.
`save_to = trash` creates it under the platform trash location.

`zipy_saved_original_paths.txt` records each moved file as a saved-folder
relative path pointing back to the original full path:

```text
1F26 -> /original/full/path/1F26
```

## Config

```sh
zipy --config
zipy --config on_conflict=ask
zipy --config on_conflict=save
zipy --config save_to=trash
```

The default config file is `~/.zipy/config`. Set `ZIPY_CONFIG` to use another
config file path.

Environment variables override the config file:

```sh
ZIPY_ON_CONFLICT=skip zipy archive.zip -d target
ZIPY_SAVE_TO=home zipy archive.zip -d target
```

Command line options override both config and environment values:

```sh
zipy archive.zip -d target --on-conflict overwrite
zipy archive.zip -d target --on-conflict ask
zipy archive.zip -d target --save-to trash
```

## Library

```c
#include <zipy/zip.h>

zipy_archive_t *zip = zipy_open("archive.zip");
zipy_extract_all(zip, "target", NULL);
zipy_close(zip);
```

Use `zipy_file_count(zip)` and `zipy_uncompressed_size(zip)` for progress or
space checks. `zipy_count(zip)` returns all entries, including directories.

Use `zipy_extract_all()` or `zipy_extract_to()` to set conflict
behavior explicitly:

```c
zipy_extract_options_t options = {
  .on_conflict = ZIPY_CONFLICT_SAVE,
  .save_to = ZIPY_SAVE_TARGET,
  .save_dir = NULL,
  .flags = ZIPY_EXTRACT_FAST,
  .password = NULL,
  .jobs = 0,
  .progress = NULL,
  .userdata = NULL
};

zipy_archive_t *zip = zipy_open("archive.zip");
zipy_extract_all(zip, "target", &options);
zipy_close(zip);
```

`ask` is CLI-only. Apps should show their own UI and pass `save`,
`overwrite`, `skip`, or `fail`.

Set `progress` to receive cumulative extracted-byte updates after each file.
Return zero from the callback to cancel extraction; zipy returns
`ZIPY_ZIP_ECANCEL`. `zipy_extract_stream()` reports `total = 0` because the
central directory may not be available yet. With `jobs > 1`, callbacks may run
from worker threads.

```c
static int
on_progress(void *userdata,
            const zipy_entry_t *entry,
            uint64_t done,
            uint64_t total) {
  (void)userdata;
  (void)entry;
  (void)done;
  (void)total;
  return 1; /* nonzero continues */
}
```

Use `zipy_extract_stream(path, target, options)` to walk local file headers
instead of opening the central directory first. This is the first streaming
primitive: it works for local headers that already carry compressed and
uncompressed sizes, including data-descriptor entries when those sizes are
still present in the local header or ZIP64 extra. For data-descriptor entries
with unknown local sizes, `zipy_extract_stream()` can stream unencrypted
Deflate method 8, legacy ZipCrypto Deflate, and WinZip AES Deflate entries
before the central directory is available. It can also stream stored entries
when the data descriptor has the optional signature. Unsigned stored,
ZIP64-sized, and resume-mode unknown-size descriptors still require the central
directory path.

CRC32 validation is enabled by default. Set `ZIPY_EXTRACT_NO_CRC` only when
lower latency matters more than detecting corrupted archive data.

Mode and timestamp restoration is enabled by default. Set
`ZIPY_EXTRACT_NO_METADATA` when raw extraction latency matters more than
preserving file metadata.

Set `ZIPY_EXTRACT_ATOMIC` to write regular files under
`target/.zipy/parts/` and rename them into place only after successful
extraction. Set `ZIPY_EXTRACT_RESUME` to keep those `.part` files after
failures, treat existing target files as resume state, and resume stored,
unencrypted entries by appending missing bytes. Deflated partial `.part` files
are restarted unless they are already complete and pass CRC validation, or CRC
is disabled.

When resume is enabled, zipy also writes `target/.zipy/resume_state.txt` with
the last entry, target path, `.part` path, resume offset, sizes, CRC, and flags.
The CLI writes `target/.zipy/resume_options.txt` with the effective options and
relevant `ZIPY_*` environment values. Password values are never written.
With atomic or resume extraction enabled, zipy's internal paths under
`.zipy/parts/`, `.zipy/resume_state.txt`, and `.zipy/resume_options.txt` are
reserved; other archive entries under `.zipy/` can still be extracted.

For raw speed, use `ZIPY_EXTRACT_FAST` in the library. It combines
`ZIPY_EXTRACT_NO_CRC` and `ZIPY_EXTRACT_NO_METADATA`. In the CLI, `--fast`
also disables progress output. It does not change conflict handling.

Set `jobs = 0` for adaptive worker selection, or pass an explicit worker count.
Deflated entries use mmap input when available; the non-mmap path feeds defl
incrementally with `infl_stream()` instead of buffering the full compressed
member.

## Status

- [x] open ZIP central directory
- [x] extract stored entries
- [x] extract deflated entries
- [x] CRC32 validation
- [x] basic ZIP64 central directory parsing
- [x] legacy ZipCrypto decryption
- [x] WinZip AES decryption
- [x] symlinks, attributes, and timestamps
- [x] chunked non-mmap deflate input
- [x] sequential local-header extraction for known-size entries
- [x] known-size data descriptors in local-header streaming
- [x] unknown-size Deflate, ZipCrypto, and AES data descriptors before central directory
- [x] signed unknown-size stored data descriptors before central directory
- [ ] unsigned unknown-size stored data descriptors before central directory
- [ ] Deflate64 method 9 extraction
