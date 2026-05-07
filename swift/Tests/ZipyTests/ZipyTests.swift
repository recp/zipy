import Foundation
import Testing
import Zipy

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

private func temporaryDirectory() throws -> URL {
  let url = FileManager.default.temporaryDirectory
    .appendingPathComponent("zipy-swift-tests", isDirectory: true)
    .appendingPathComponent(UUID().uuidString, isDirectory: true)
  try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
  return url
}

private func runZip(in directory: URL, archive: URL) throws {
  let process = Process()
  process.executableURL = URL(fileURLWithPath: "/usr/bin/zip")
  process.currentDirectoryURL = directory
  process.arguments = ["-qr", archive.path, "."]
  try process.run()
  process.waitUntilExit()

  if process.terminationStatus != 0 {
    throw ZipTestError.zipFailed(process.terminationStatus)
  }
}

private enum ZipTestError: Error {
  case zipFailed(Int32)
}
