#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

use std::ffi::{c_char, c_int, c_void};

pub enum zipy_archive_t {}

pub const ZIPY_VERSION_MAJOR: u32 = 0;
pub const ZIPY_VERSION_MINOR: u32 = 1;
pub const ZIPY_VERSION_PATCH: u32 = 0;
pub const ZIPY_VERSION: u32 =
    ZIPY_VERSION_MAJOR * 10_000 + ZIPY_VERSION_MINOR * 100 + ZIPY_VERSION_PATCH;

pub const ZIPY_ZIP_OK: c_int = 0;
pub const ZIPY_ZIP_SAVED: c_int = 1;
pub const ZIPY_ZIP_SKIPPED: c_int = 2;
pub const ZIPY_ZIP_ERR: c_int = -1;
pub const ZIPY_ZIP_EINFLATE: c_int = -2;
pub const ZIPY_ZIP_ESIZE: c_int = -3;
pub const ZIPY_ZIP_ECRC: c_int = -4;
pub const ZIPY_ZIP_EFILE: c_int = -5;
pub const ZIPY_ZIP_EUNSUP: c_int = -6;
pub const ZIPY_ZIP_EEXIST: c_int = -7;
pub const ZIPY_ZIP_EPASS: c_int = -8;
pub const ZIPY_ZIP_EAUTH: c_int = -9;
pub const ZIPY_ZIP_ENOSPC: c_int = -10;
pub const ZIPY_ZIP_ECANCEL: c_int = -11;
pub const ZIPY_ZIP_EINCOMPLETE: c_int = -12;

pub const ZIPY_ZIP_STORE: u16 = 0;
pub const ZIPY_ZIP_DEFLATE: u16 = 8;
pub const ZIPY_ZIP_DEFLATE64: u16 = 9;

pub const ZIPY_SAVE_TARGET: c_int = 0;
pub const ZIPY_SAVE_HOME: c_int = 1;
pub const ZIPY_SAVE_TRASH: c_int = 2;

pub const ZIPY_CONFLICT_SAVE: c_int = 0;
pub const ZIPY_CONFLICT_OVERWRITE: c_int = 1;
pub const ZIPY_CONFLICT_SKIP: c_int = 2;
pub const ZIPY_CONFLICT_FAIL: c_int = 3;

pub const ZIPY_EXTRACT_DEFAULT: u32 = 0;
pub const ZIPY_EXTRACT_NO_CRC: u32 = 1 << 0;
pub const ZIPY_EXTRACT_NO_METADATA: u32 = 1 << 1;
pub const ZIPY_EXTRACT_ATOMIC: u32 = 1 << 2;
pub const ZIPY_EXTRACT_RESUME: u32 = 1 << 3;
pub const ZIPY_EXTRACT_UNSAFE_SYMLINKS: u32 = 1 << 4;
pub const ZIPY_EXTRACT_FAST: u32 = ZIPY_EXTRACT_NO_CRC | ZIPY_EXTRACT_NO_METADATA;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct zipy_entry_t {
    pub name: *const c_char,
    pub name_len: usize,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub crc32: u32,
    pub method: u16,
    pub is_directory: bool,
    pub encrypted: bool,
}

pub type zipy_progress_t = Option<
    unsafe extern "C" fn(
        userdata: *mut c_void,
        entry: *const zipy_entry_t,
        done: u64,
        total: u64,
    ) -> c_int,
>;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct zipy_extract_options_t {
    pub on_conflict: c_int,
    pub save_to: c_int,
    pub save_dir: *const c_char,
    pub flags: u32,
    pub password: *const c_char,
    pub jobs: usize,
    pub progress: zipy_progress_t,
    pub userdata: *mut c_void,
}

extern "C" {
    pub fn zipy_extract_options_init(options: *mut zipy_extract_options_t);
    pub fn zipy_open(path: *const c_char) -> *mut zipy_archive_t;
    pub fn zipy_count(zipy: *const zipy_archive_t) -> usize;
    pub fn zipy_file_count(zipy: *const zipy_archive_t) -> usize;
    pub fn zipy_uncompressed_size(zipy: *const zipy_archive_t) -> u64;
    pub fn zipy_entry(zipy: *const zipy_archive_t, index: usize) -> *const zipy_entry_t;
    pub fn zipy_extract(zipy: *mut zipy_archive_t, index: usize, destpath: *const c_char) -> c_int;
    pub fn zipy_extract_to(
        zipy: *mut zipy_archive_t,
        index: usize,
        destdir: *const c_char,
        options: *const zipy_extract_options_t,
    ) -> c_int;
    pub fn zipy_extract_named(
        zipy: *mut zipy_archive_t,
        name: *const c_char,
        destpath: *const c_char,
    ) -> c_int;
    pub fn zipy_extract_all(
        zipy: *mut zipy_archive_t,
        destdir: *const c_char,
        options: *const zipy_extract_options_t,
    ) -> c_int;
    pub fn zipy_extract_stream(
        path: *const c_char,
        destdir: *const c_char,
        options: *const zipy_extract_options_t,
    ) -> c_int;
    pub fn zipy_strerror(result: c_int) -> *const c_char;
    pub fn zipy_close(zipy: *mut zipy_archive_t);
}
