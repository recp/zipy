use std::borrow::Cow;
use std::ffi::OsString;
use std::ffi::{CStr, CString, NulError};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::slice;
use std::str;

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

pub type Result<T> = std::result::Result<T, Error>;

pub const VERSION_MAJOR: u32 = zipy_sys::ZIPY_VERSION_MAJOR;
pub const VERSION_MINOR: u32 = zipy_sys::ZIPY_VERSION_MINOR;
pub const VERSION_PATCH: u32 = zipy_sys::ZIPY_VERSION_PATCH;
pub const VERSION: u32 = zipy_sys::ZIPY_VERSION;
pub const VERSION_STRING: &str = "0.1.1";

#[derive(Debug)]
pub enum Error {
    OpenFailed(PathBuf),
    InvalidPath(PathBuf),
    InvalidString,
    InflateFailed,
    SizeMismatch,
    CrcFailed,
    FileOperationFailed,
    UnsupportedFeature,
    FileExists,
    PasswordRequiredOrIncorrect,
    AuthenticationFailed,
    NoSpace,
    Cancelled,
    Incomplete,
    OperationFailed { code: i32, message: String },
}

impl Error {
    fn from_code(code: i32) -> Self {
        match code {
            zipy_sys::ZIPY_ZIP_EINFLATE => Self::InflateFailed,
            zipy_sys::ZIPY_ZIP_ESIZE => Self::SizeMismatch,
            zipy_sys::ZIPY_ZIP_ECRC => Self::CrcFailed,
            zipy_sys::ZIPY_ZIP_EFILE => Self::FileOperationFailed,
            zipy_sys::ZIPY_ZIP_EUNSUP => Self::UnsupportedFeature,
            zipy_sys::ZIPY_ZIP_EEXIST => Self::FileExists,
            zipy_sys::ZIPY_ZIP_EPASS => Self::PasswordRequiredOrIncorrect,
            zipy_sys::ZIPY_ZIP_EAUTH => Self::AuthenticationFailed,
            zipy_sys::ZIPY_ZIP_ENOSPC => Self::NoSpace,
            zipy_sys::ZIPY_ZIP_ECANCEL => Self::Cancelled,
            zipy_sys::ZIPY_ZIP_EINCOMPLETE => Self::Incomplete,
            _ => Self::OperationFailed {
                code,
                message: strerror(code),
            },
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenFailed(path) => write!(f, "cannot open zip archive: {}", path.display()),
            Self::InvalidPath(path) => {
                write!(f, "path contains an interior NUL byte: {}", path.display())
            }
            Self::InvalidString => write!(f, "string contains an interior NUL byte"),
            Self::InflateFailed => f.write_str("inflate failed"),
            Self::SizeMismatch => f.write_str("zip entry size mismatch"),
            Self::CrcFailed => f.write_str("crc check failed"),
            Self::FileOperationFailed => f.write_str("file operation failed"),
            Self::UnsupportedFeature => f.write_str("unsupported zip feature"),
            Self::FileExists => f.write_str("target file exists"),
            Self::PasswordRequiredOrIncorrect => f.write_str("password required or incorrect"),
            Self::AuthenticationFailed => f.write_str("authentication failed"),
            Self::NoSpace => f.write_str("no space left on device"),
            Self::Cancelled => f.write_str("operation cancelled"),
            Self::Incomplete => f.write_str("incomplete zip stream"),
            Self::OperationFailed { code, message } => write!(f, "{message} ({code})"),
        }
    }
}

impl std::error::Error for Error {}

impl From<NulError> for Error {
    fn from(_: NulError) -> Self {
        Self::InvalidString
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConflictPolicy {
    Save,
    Overwrite,
    Skip,
    Fail,
}

impl ConflictPolicy {
    fn raw(self) -> i32 {
        match self {
            Self::Save => zipy_sys::ZIPY_CONFLICT_SAVE,
            Self::Overwrite => zipy_sys::ZIPY_CONFLICT_OVERWRITE,
            Self::Skip => zipy_sys::ZIPY_CONFLICT_SKIP,
            Self::Fail => zipy_sys::ZIPY_CONFLICT_FAIL,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SaveLocation {
    Target,
    Home,
    Trash,
}

impl SaveLocation {
    fn raw(self) -> i32 {
        match self {
            Self::Target => zipy_sys::ZIPY_SAVE_TARGET,
            Self::Home => zipy_sys::ZIPY_SAVE_HOME,
            Self::Trash => zipy_sys::ZIPY_SAVE_TRASH,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Options {
    conflict: ConflictPolicy,
    save_to: SaveLocation,
    save_dir: Option<PathBuf>,
    flags: u32,
    password: Option<String>,
    jobs: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            conflict: ConflictPolicy::Save,
            save_to: SaveLocation::Target,
            save_dir: None,
            flags: zipy_sys::ZIPY_EXTRACT_DEFAULT,
            password: None,
            jobs: 0,
        }
    }
}

impl Options {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn fast() -> Self {
        Self::default().no_crc().no_metadata()
    }

    pub fn no_crc(mut self) -> Self {
        self.flags |= zipy_sys::ZIPY_EXTRACT_NO_CRC;
        self
    }

    pub fn no_metadata(mut self) -> Self {
        self.flags |= zipy_sys::ZIPY_EXTRACT_NO_METADATA;
        self
    }

    pub fn atomic(mut self) -> Self {
        self.flags |= zipy_sys::ZIPY_EXTRACT_ATOMIC;
        self
    }

    pub fn resume(mut self) -> Self {
        self.flags |= zipy_sys::ZIPY_EXTRACT_RESUME;
        self
    }

    pub fn unsafe_symlinks(mut self) -> Self {
        self.flags |= zipy_sys::ZIPY_EXTRACT_UNSAFE_SYMLINKS;
        self
    }

    pub fn conflict(mut self, policy: ConflictPolicy) -> Self {
        self.conflict = policy;
        self
    }

    pub fn overwrite(self) -> Self {
        self.conflict(ConflictPolicy::Overwrite)
    }

    pub fn skip(self) -> Self {
        self.conflict(ConflictPolicy::Skip)
    }

    pub fn fail_on_conflict(self) -> Self {
        self.conflict(ConflictPolicy::Fail)
    }

    pub fn save_to(mut self, location: SaveLocation) -> Self {
        self.save_to = location;
        self
    }

    pub fn save_dir<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.save_dir = Some(path.into());
        self
    }

    pub fn password<S: Into<String>>(mut self, password: S) -> Self {
        self.password = Some(password.into());
        self
    }

    pub fn jobs(mut self, jobs: usize) -> Self {
        self.jobs = jobs;
        self
    }
}

struct PreparedOptions {
    raw: zipy_sys::zipy_extract_options_t,
    _save_dir: Option<CString>,
    _password: Option<CString>,
}

impl PreparedOptions {
    fn new(options: &Options) -> Result<Self> {
        let save_dir = options
            .save_dir
            .as_deref()
            .map(path_to_cstring)
            .transpose()?;
        let password = options
            .password
            .as_ref()
            .map(|value| CString::new(value.as_bytes()))
            .transpose()?;

        let mut raw = unsafe {
            let mut raw = std::mem::zeroed();
            zipy_sys::zipy_extract_options_init(&mut raw);
            raw
        };
        raw.on_conflict = options.conflict.raw();
        raw.save_to = options.save_to.raw();
        raw.flags = options.flags;
        raw.jobs = options.jobs;
        if let Some(value) = &save_dir {
            raw.save_dir = value.as_ptr();
        }
        if let Some(value) = &password {
            raw.password = value.as_ptr();
        }

        Ok(Self {
            raw,
            _save_dir: save_dir,
            _password: password,
        })
    }
}

pub struct Archive {
    raw: NonNull<zipy_sys::zipy_archive_t>,
}

impl Archive {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let archive_path = path.as_ref();
        let c_path = path_to_cstring(archive_path)?;
        let raw = unsafe { zipy_sys::zipy_open(c_path.as_ptr()) };

        NonNull::new(raw)
            .map(|raw| Self { raw })
            .ok_or_else(|| Error::OpenFailed(archive_path.to_path_buf()))
    }

    pub fn len(&self) -> usize {
        unsafe { zipy_sys::zipy_count(self.raw.as_ptr()) }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn file_count(&self) -> usize {
        unsafe { zipy_sys::zipy_file_count(self.raw.as_ptr()) }
    }

    pub fn uncompressed_size(&self) -> u64 {
        unsafe { zipy_sys::zipy_uncompressed_size(self.raw.as_ptr()) }
    }

    pub fn entry(&self, index: usize) -> Option<Entry<'_>> {
        let raw = unsafe { zipy_sys::zipy_entry(self.raw.as_ptr(), index) };
        unsafe { Entry::from_ptr(raw) }
    }

    pub fn entries(&self) -> Entries<'_> {
        Entries {
            archive: self,
            index: 0,
            len: self.len(),
        }
    }

    pub fn extract_all<P: AsRef<Path>>(&mut self, target: P, options: Options) -> Result<()> {
        let target = path_to_cstring(target.as_ref())?;
        let prepared = PreparedOptions::new(&options)?;
        let ret = unsafe {
            zipy_sys::zipy_extract_all(self.raw.as_ptr(), target.as_ptr(), &prepared.raw)
        };
        check(ret)
    }

    pub fn extract_all_with_progress<P, F>(
        &mut self,
        target: P,
        options: Options,
        progress: F,
    ) -> Result<()>
    where
        P: AsRef<Path>,
        F: Fn(Progress<'_>) -> bool + Send + Sync,
    {
        let target = path_to_cstring(target.as_ref())?;
        let mut prepared = PreparedOptions::new(&options)?;
        prepared.raw.progress = Some(progress_trampoline::<F>);
        prepared.raw.userdata = &progress as *const F as *mut _;
        let ret = unsafe {
            zipy_sys::zipy_extract_all(self.raw.as_ptr(), target.as_ptr(), &prepared.raw)
        };
        check(ret)
    }
}

impl Drop for Archive {
    fn drop(&mut self) {
        unsafe {
            zipy_sys::zipy_close(self.raw.as_ptr());
        }
    }
}

pub struct Entries<'a> {
    archive: &'a Archive,
    index: usize,
    len: usize,
}

impl<'a> Iterator for Entries<'a> {
    type Item = Entry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.len {
            return None;
        }

        let entry = self.archive.entry(self.index);
        self.index += 1;
        entry
    }
}

#[derive(Clone, Copy)]
pub struct Entry<'a> {
    raw: &'a zipy_sys::zipy_entry_t,
}

impl<'a> Entry<'a> {
    unsafe fn from_ptr(raw: *const zipy_sys::zipy_entry_t) -> Option<Self> {
        raw.as_ref().map(|raw| Self { raw })
    }

    pub fn name_bytes(&self) -> &'a [u8] {
        if self.raw.name.is_null() || self.raw.name_len == 0 {
            return &[];
        }
        unsafe { slice::from_raw_parts(self.raw.name as *const u8, self.raw.name_len) }
    }

    pub fn name(&self) -> std::result::Result<&'a str, str::Utf8Error> {
        str::from_utf8(self.name_bytes())
    }

    pub fn name_lossy(&self) -> Cow<'a, str> {
        String::from_utf8_lossy(self.name_bytes())
    }

    pub fn compressed_size(&self) -> u64 {
        self.raw.compressed_size
    }

    pub fn uncompressed_size(&self) -> u64 {
        self.raw.uncompressed_size
    }

    pub fn crc32(&self) -> u32 {
        self.raw.crc32
    }

    pub fn method(&self) -> u16 {
        self.raw.method
    }

    pub fn is_directory(&self) -> bool {
        self.raw.is_directory
    }

    pub fn encrypted(&self) -> bool {
        self.raw.encrypted
    }
}

pub struct Progress<'a> {
    pub entry: Option<Entry<'a>>,
    pub done: u64,
    pub total: u64,
}

impl Progress<'_> {
    pub fn fraction(&self) -> Option<f64> {
        if self.total == 0 {
            None
        } else {
            Some((self.done as f64 / self.total as f64).min(1.0))
        }
    }
}

pub fn extract<A: AsRef<Path>, T: AsRef<Path>>(
    archive: A,
    target: T,
    options: Options,
) -> Result<()> {
    let mut archive = Archive::open(archive)?;
    archive.extract_all(target, options)
}

pub fn extract_stream<A: AsRef<Path>, T: AsRef<Path>>(
    archive: A,
    target: T,
    options: Options,
) -> Result<()> {
    let archive = path_to_cstring(archive.as_ref())?;
    let target = path_to_cstring(target.as_ref())?;
    let prepared = PreparedOptions::new(&options)?;
    let ret =
        unsafe { zipy_sys::zipy_extract_stream(archive.as_ptr(), target.as_ptr(), &prepared.raw) };
    check(ret)
}

pub fn extract_stream_with_progress<A, T, F>(
    archive: A,
    target: T,
    options: Options,
    progress: F,
) -> Result<()>
where
    A: AsRef<Path>,
    T: AsRef<Path>,
    F: Fn(Progress<'_>) -> bool + Send + Sync,
{
    let archive = path_to_cstring(archive.as_ref())?;
    let target = path_to_cstring(target.as_ref())?;
    let mut prepared = PreparedOptions::new(&options)?;
    prepared.raw.progress = Some(progress_trampoline::<F>);
    prepared.raw.userdata = &progress as *const F as *mut _;
    let ret =
        unsafe { zipy_sys::zipy_extract_stream(archive.as_ptr(), target.as_ptr(), &prepared.raw) };
    check(ret)
}

unsafe extern "C" fn progress_trampoline<F>(
    userdata: *mut std::ffi::c_void,
    entry: *const zipy_sys::zipy_entry_t,
    done: u64,
    total: u64,
) -> i32
where
    F: Fn(Progress<'_>) -> bool + Send + Sync,
{
    let callback = &*(userdata as *const F);
    let progress = Progress {
        entry: Entry::from_ptr(entry),
        done,
        total,
    };
    if callback(progress) {
        1
    } else {
        0
    }
}

fn check(code: i32) -> Result<()> {
    if code >= zipy_sys::ZIPY_ZIP_OK {
        Ok(())
    } else {
        Err(Error::from_code(code))
    }
}

fn strerror(code: i32) -> String {
    unsafe {
        let ptr = zipy_sys::zipy_strerror(code);
        if ptr.is_null() {
            return "zipy error".to_string();
        }
        CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}

#[cfg(unix)]
fn path_to_cstring(path: &Path) -> Result<CString> {
    let path = canonical_path(path);
    CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::InvalidPath(path))
}

#[cfg(not(unix))]
fn path_to_cstring(path: &Path) -> Result<CString> {
    let path = canonical_path(path);
    CString::new(path.to_string_lossy().as_bytes()).map_err(|_| Error::InvalidPath(path))
}

fn canonical_path(path: &Path) -> PathBuf {
    if let Ok(resolved) = fs::canonicalize(path) {
        return resolved;
    }

    let mut suffixes: Vec<OsString> = Vec::new();
    let mut current = path;

    loop {
        if let Some(name) = current.file_name() {
            suffixes.push(name.to_os_string());
        }

        let Some(parent) = current.parent() else {
            break;
        };

        if let Ok(mut resolved) = fs::canonicalize(parent) {
            for suffix in suffixes.iter().rev() {
                resolved.push(suffix);
            }
            return resolved;
        }

        if parent == current {
            break;
        }
        current = parent;
    }

    path.to_path_buf()
}
