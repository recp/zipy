# zipy

zipy is a small, fast ZIP extractor and C library. It reads ZIP central
directories, extracts stored and deflated entries, validates CRC32, and keeps
existing files safe on conflicts.

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
zipy archive.zip -d target -j auto
zipy archive.zip -d target -j 1
zipy archive.zip -d target -p password
zipy archive.zip -d target --no-crc
```

By default, the CLI asks what to do when an extracted entry would replace an
existing file. Non-interactive runs fall back to saving existing files before
writing new files.

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
zipy_extract_all(zip, "target");
zipy_close(zip);
```

Use `zipy_extract_all_options()` or `zipy_extract_to()` to set conflict
behavior explicitly:

```c
zipy_extract_options_t options = {
  .on_conflict = ZIPY_CONFLICT_SAVE,
  .save_to = ZIPY_SAVE_TARGET,
  .save_dir = NULL,
  .flags = ZIPY_EXTRACT_DEFAULT,
  .password = NULL
};

zipy_archive_t *zip = zipy_open("archive.zip");
zipy_extract_all_options(zip, "target", &options);
zipy_close(zip);
```

`ask` is CLI-only. Apps should show their own UI and pass `save`,
`overwrite`, `skip`, or `fail`.

CRC32 validation is enabled by default. Set `ZIPY_EXTRACT_NO_CRC` only when
lower latency matters more than detecting corrupted archive data.

## Status

- [x] open ZIP central directory
- [x] extract stored entries
- [x] extract deflated entries
- [x] CRC32 validation
- [x] basic ZIP64 central directory parsing
- [x] legacy ZipCrypto decryption
- [ ] WinZip AES decryption
- [ ] Deflate64
- [ ] symlinks, attributes, and timestamps
