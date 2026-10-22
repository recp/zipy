import Foundation
import Testing
import Zipy
import CZipy

@Test
func indexedModificationTime() throws {
  let root = try temporaryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }
  let source = root.appendingPathComponent("source", isDirectory: true)
  let archive = root.appendingPathComponent("archive.zip")
  let file = source.appendingPathComponent("data.bin")
  let modified = Date(timeIntervalSince1970: 1_600_000_001)
  try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
  try Data("payload".utf8).write(to: file)
  try FileManager.default.setAttributes([.modificationDate: modified], ofItemAtPath: file.path)
  try runZip(in: source, archive: archive)

  let handle = try #require(archive.withUnsafeFileSystemRepresentation { zipy_open($0) })
  defer { zipy_close(handle) }
  var timestamp: Int64 = 0
  #expect(zipy_entry_mtime(handle, 0, &timestamp))
  #expect(timestamp == Int64(modified.timeIntervalSince1970))
  #expect(!zipy_entry_mtime(handle, zipy_count(handle), &timestamp))
  #expect(!zipy_entry_mtime(nil, 0, &timestamp))
  #expect(!zipy_entry_mtime(handle, 0, nil))
}

@Test
func indexedExtractionReadsLocalHeaders() throws {
  let root = try temporaryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }
  let source = root.appendingPathComponent("source", isDirectory: true)
  let contents = Data(repeating: 0x41, count: 4096)
  try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
  try contents.write(to: source.appendingPathComponent("data.bin"))

  for stored in [false, true] {
    let archive = root.appendingPathComponent(stored ? "stored.zip" : "deflated.zip")
    let output = root.appendingPathComponent(stored ? "stored" : "deflated")
    try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
    try runZip(in: source, archive: archive, storing: stored)
    let handle = try #require(archive.withUnsafeFileSystemRepresentation { zipy_open($0) })
    defer { zipy_close(handle) }
    let entry = try #require(zipy_entry(handle, 0))
    #expect(entry.pointee.method == (stored ? 0 : 8))
    let result = output.withUnsafeFileSystemRepresentation {
      zipy_extract_to(handle, 0, $0, nil)
    }
    #expect(result == ZIPY_ZIP_OK.rawValue)
    #expect(try Data(contentsOf: output.appendingPathComponent("data.bin")) == contents)
  }
}

@Test
func indexedExtractionRejectsInvalidLocalHeader() throws {
  let root = try temporaryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }
  let source = root.appendingPathComponent("source", isDirectory: true)
  let archive = root.appendingPathComponent("archive.zip")
  let output = root.appendingPathComponent("output", isDirectory: true)
  try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
  try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
  try Data("payload".utf8).write(to: source.appendingPathComponent("data.bin"))
  try runZip(in: source, archive: archive)
  var bytes = try Data(contentsOf: archive)
  bytes[0] = 0
  try bytes.write(to: archive)

  let handle = try #require(archive.withUnsafeFileSystemRepresentation { zipy_open($0) })
  defer { zipy_close(handle) }
  let result = output.withUnsafeFileSystemRepresentation {
    zipy_extract_to(handle, 0, $0, nil)
  }
  #expect(result == ZIPY_ZIP_EFILE.rawValue)
  #expect(!FileManager.default.fileExists(atPath: output.appendingPathComponent("data.bin").path))
}

@Test
func extractFast() async throws {
  let root = try temporaryDirectory()
  let source = root.appendingPathComponent("source", isDirectory: true)
  let output = root.appendingPathComponent("output", isDirectory: true)
  let archive = root.appendingPathComponent("archive.zip")

  try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
  try "hello zipy".write(
    to: source.appendingPathComponent("hello.txt"),
    atomically: true,
    encoding: .utf8
  )
  try runZip(in: source, archive: archive)

  let progress = Progress(totalUnitCount: 0)
  let observer = ZipyProgressActor()

  try await Zipy.extract(
    archive,
    to: output,
    options: .fast,
    conflict: .overwrite,
    progress: progress,
    observer: observer
  ) { state in
    #expect(state.completedBytes <= max(state.totalBytes, state.completedBytes))
    return true
  }

  let text = try String(
    contentsOf: output.appendingPathComponent("hello.txt"),
    encoding: .utf8
  )
  #expect(text == "hello zipy")
  let latest = await observer.latest
  #expect(latest?.completedBytes ?? 0 > 0)
  #expect(progress.completedUnitCount >= 0)
}

@Test
func actorProgress() async throws {
  let root = try temporaryDirectory()
  let source = root.appendingPathComponent("source", isDirectory: true)
  let output = root.appendingPathComponent("output", isDirectory: true)
  let archive = root.appendingPathComponent("archive.zip")
  let observer = ZipyProgressActor()

  try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
  try Data(repeating: 0x41, count: 4096)
    .write(to: source.appendingPathComponent("data.bin"))
  try runZip(in: source, archive: archive)

  try await Zipy.extract(
    archive,
    to: output,
    options: .fast,
    conflict: .overwrite,
    observer: observer
  )

  let latest = await observer.latest
  #expect(latest?.completedBytes ?? 0 > 0)
  #expect(FileManager.default.fileExists(atPath: output.appendingPathComponent("data.bin").path))
}

@Test
func containedSymlinkExtracts() async throws {
  let root = try temporaryDirectory()
  let source = root.appendingPathComponent("source", isDirectory: true)
  let output = root.appendingPathComponent("output", isDirectory: true)
  let archive = root.appendingPathComponent("archive.zip")
  let link = output.appendingPathComponent("link")

  try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
  try "hello".write(
    to: source.appendingPathComponent("file.txt"),
    atomically: true,
    encoding: .utf8
  )
  try FileManager.default.createSymbolicLink(
    atPath: source.appendingPathComponent("link").path,
    withDestinationPath: "file.txt"
  )
  try runZip(in: source, archive: archive, preservingSymlinks: true)

  try await Zipy.extract(
    archive,
    to: output,
    options: .fast,
    conflict: .overwrite
  )

  let values = try link.resourceValues(forKeys: [.isSymbolicLinkKey])
  #expect(values.isSymbolicLink == true)
  #expect(try FileManager.default.destinationOfSymbolicLink(atPath: link.path) == "file.txt")
}

@Test
func externalSymlinkIsRejected() async throws {
  let root = try temporaryDirectory()
  let source = root.appendingPathComponent("source", isDirectory: true)
  let output = root.appendingPathComponent("output", isDirectory: true)
  let archive = root.appendingPathComponent("archive.zip")

  try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
  try FileManager.default.createSymbolicLink(
    atPath: source.appendingPathComponent("link").path,
    withDestinationPath: "/etc"
  )
  try runZip(in: source, archive: archive, preservingSymlinks: true)

  var error: Zipy.Error?
  do {
    try await Zipy.extract(
      archive,
      to: output,
      options: .fast,
      conflict: .overwrite
    )
  } catch let zipError as Zipy.Error {
    error = zipError
  }

  #expect(error == .fileOperationFailed)
  #expect(!FileManager.default.fileExists(atPath: output.appendingPathComponent("link").path))
}

@Test
func unsafeRootFSSymlinkExtracts() async throws {
  let root = try temporaryDirectory()
  let source = root.appendingPathComponent("source", isDirectory: true)
  let output = root.appendingPathComponent("output", isDirectory: true)
  let archive = root.appendingPathComponent("archive.zip")
  let link = output.appendingPathComponent("link")

  try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
  try FileManager.default.createSymbolicLink(
    atPath: source.appendingPathComponent("link").path,
    withDestinationPath: "/etc"
  )
  try runZip(in: source, archive: archive, preservingSymlinks: true)

  try await Zipy.extract(
    archive,
    to: output,
    options: .fast,
    conflict: .overwrite,
    symlinkPolicy: .unsafeRootFS
  )

  let values = try link.resourceValues(forKeys: [.isSymbolicLinkKey])
  #expect(values.isSymbolicLink == true)
  #expect(try FileManager.default.destinationOfSymbolicLink(atPath: link.path) == "/etc")
}

private func temporaryDirectory() throws -> URL {
  let url = FileManager.default.temporaryDirectory
    .appendingPathComponent("zipy-swift-tests", isDirectory: true)
    .appendingPathComponent(UUID().uuidString, isDirectory: true)
  try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
  return url
}

private func runZip(
  in directory: URL,
  archive: URL,
  preservingSymlinks: Bool = false,
  storing: Bool = false
) throws {
  let process = Process()
  process.executableURL = URL(fileURLWithPath: "/usr/bin/zip")
  process.currentDirectoryURL = directory
  process.arguments = preservingSymlinks
    ? ["-qry", archive.path, "."]
    : ["-qr", archive.path, "."]
  if storing { process.arguments?.insert("-0", at: 0) }
  try process.run()
  process.waitUntilExit()

  if process.terminationStatus != 0 {
    throw ZipTestError.zipFailed(process.terminationStatus)
  }
}

private enum ZipTestError: Error {
  case zipFailed(Int32)
}
