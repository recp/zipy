use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

#[test]
fn extract_stored_zip_fast() {
    let root = temp_dir("extract_stored_zip_fast");
    let archive = root.join("sample.zip");
    let out = root.join("out");

    write_stored_zip(&archive, "hello.txt", b"hello zipy").unwrap();
    fs::create_dir_all(&out).unwrap();
    zipy::extract(&archive, &out, zipy::Options::fast().overwrite()).unwrap();

    assert_eq!(fs::read(out.join("hello.txt")).unwrap(), b"hello zipy");
    assert_eq!(zipy::VERSION_STRING, "0.1.1");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn archive_entries_are_readable() {
    let root = temp_dir("archive_entries_are_readable");
    let archive_path = root.join("sample.zip");

    write_stored_zip(&archive_path, "dir/file.txt", b"content").unwrap();
    let archive = zipy::Archive::open(&archive_path).unwrap();
    let names: Vec<_> = archive
        .entries()
        .map(|entry| entry.name_lossy().into_owned())
        .collect();

    assert_eq!(archive.file_count(), 1);
    assert_eq!(names, ["dir/file.txt"]);

    let _ = fs::remove_dir_all(root);
}

fn temp_dir(name: &str) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("zipy-rust-{name}-{now}-{id}"));
    fs::create_dir_all(&path).unwrap();
    path
}

fn write_stored_zip(path: &Path, name: &str, data: &[u8]) -> io::Result<()> {
    let mut bytes = Vec::new();
    let name = name.as_bytes();
    let data_len = data.len() as u32;

    push_u32(&mut bytes, 0x0403_4b50);
    push_u16(&mut bytes, 20);
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 0);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, data_len);
    push_u32(&mut bytes, data_len);
    push_u16(&mut bytes, name.len() as u16);
    push_u16(&mut bytes, 0);
    bytes.extend_from_slice(name);
    bytes.extend_from_slice(data);

    let central_offset = bytes.len() as u32;
    push_u32(&mut bytes, 0x0201_4b50);
    push_u16(&mut bytes, 20);
    push_u16(&mut bytes, 20);
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 0);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, data_len);
    push_u32(&mut bytes, data_len);
    push_u16(&mut bytes, name.len() as u16);
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 0);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 0);
    bytes.extend_from_slice(name);

    let central_size = bytes.len() as u32 - central_offset;
    push_u32(&mut bytes, 0x0605_4b50);
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 1);
    push_u16(&mut bytes, 1);
    push_u32(&mut bytes, central_size);
    push_u32(&mut bytes, central_offset);
    push_u16(&mut bytes, 0);

    fs::write(path, bytes)
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}
