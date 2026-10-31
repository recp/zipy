import Foundation
import Testing
import Zipy
import CZipy

@Test
func zip64OffsetCanEqualZIP32Sentinel() throws {
  let root = try temporaryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }

  let archive = root.appendingPathComponent("sentinel.zip")
  let output  = root.appendingPathComponent("payload.bin")
  let offset  = UInt64(UInt32.max)
  let name    = Data("file.bin".utf8)
  let crc: UInt32 = 0xb7b2364b // IEEE CRC32 of "X".

  func put<T: FixedWidthInteger>(_ value: T, at offset: Int, in data: inout Data) {
    var little = value.littleEndian

    withUnsafeBytes(of: &little) {
      data.replaceSubrange(offset..<(offset + $0.count), with: $0)
    }
  }

  var local = Data(count: 30)
  put(UInt32(0x04034b50), at: 0, in: &local)
  put(UInt16(45), at: 4, in: &local)
  put(UInt16(0x0800), at: 6, in: &local)
  put(UInt16(0x5021), at: 12, in: &local)
  put(crc, at: 14, in: &local)
  put(UInt32(1), at: 18, in: &local)
  put(UInt32(1), at: 22, in: &local)
  put(UInt16(name.count), at: 26, in: &local)
  local.append(name)
  local.append(88)

  var central = Data(count: 46)
  put(UInt32(0x02014b50), at: 0, in: &central)
  put(UInt16(0x032d), at: 4, in: &central)
  put(UInt16(45), at: 6, in: &central)
  put(UInt16(0x0800), at: 8, in: &central)
  put(UInt16(0x5021), at: 14, in: &central)
  put(crc, at: 16, in: &central)
  put(UInt32(1), at: 20, in: &central)
  put(UInt32(1), at: 24, in: &central)
  put(UInt16(name.count), at: 28, in: &central)
  put(UInt16(12), at: 30, in: &central)
  put(UInt32(0o100644 << 16), at: 38, in: &central)
  put(UInt32.max, at: 42, in: &central)
  central.append(name)

  var extra = Data(count: 12)
  put(UInt16(1), at: 0, in: &extra)
  put(UInt16(8), at: 2, in: &extra)
  put(offset, at: 4, in: &extra)
  central.append(extra)

  let centralOffset = offset + UInt64(local.count)
  var end = Data(count: 98)
  put(UInt32(0x06064b50), at: 0, in: &end)
  put(UInt64(44), at: 4, in: &end)
  put(UInt16(0x032d), at: 12, in: &end)
  put(UInt16(45), at: 14, in: &end)
  put(UInt64(1), at: 24, in: &end)
  put(UInt64(1), at: 32, in: &end)
  put(UInt64(central.count), at: 40, in: &end)
  put(centralOffset, at: 48, in: &end)
  put(UInt32(0x07064b50), at: 56, in: &end)
  put(centralOffset + UInt64(central.count), at: 64, in: &end)
  put(UInt32(1), at: 72, in: &end)
  put(UInt32(0x06054b50), at: 76, in: &end)
  put(UInt16(1), at: 84, in: &end)
  put(UInt16(1), at: 86, in: &end)
  put(UInt32(central.count), at: 88, in: &end)
  put(UInt32.max, at: 92, in: &end)

  _ = FileManager.default.createFile(atPath: archive.path, contents: nil)
  let file = try FileHandle(forWritingTo: archive)
  try file.seek(toOffset: offset)
  try file.write(contentsOf: local)
  try file.write(contentsOf: central)
  try file.write(contentsOf: end)
  try file.close()

  let handle = try #require(archive.withUnsafeFileSystemRepresentation { zipy_open($0) })
  defer { zipy_close(handle) }

  #expect(zipy_count(handle) == 1)
  #expect(
    output.withUnsafeFileSystemRepresentation { zipy_extract(handle, 0, $0) }
      == ZIPY_ZIP_OK.rawValue
  )
  #expect(try Data(contentsOf: output) == Data("X".utf8))
}

@Test
func parallelIndexedExtractionKeepsEveryPayload() throws {
  let root = try temporaryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }

  let source  = root.appendingPathComponent("source", isDirectory: true)
  let archive = root.appendingPathComponent("parallel.zip")
  let output  = root.appendingPathComponent("output", isDirectory: true)

  try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
  try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)

  for index in 0..<11 {
    try Data(repeating: UInt8(65 + index), count: 2 * 1024 * 1024)
      .write(to: source.appendingPathComponent("file-\(index).txt"))
  }

  try runZip(in: source, archive: archive)

  let handle = try #require(archive.withUnsafeFileSystemRepresentation { zipy_open($0) })
  defer { zipy_close(handle) }

  var options = zipy_extract_options_t()
  zipy_extract_options_init(&options)
  options.jobs        = 8
  options.on_conflict = ZIPY_CONFLICT_OVERWRITE

  let result = output.withUnsafeFileSystemRepresentation {
    zipy_extract_all(handle, $0, &options)
  }

  #expect(result == ZIPY_ZIP_OK.rawValue)

  for index in 0..<11 {
    let data = try Data(contentsOf: output.appendingPathComponent("file-\(index).txt"))

    #expect(data == Data(repeating: UInt8(65 + index), count: 2 * 1024 * 1024))
  }
}

@Test
func largePayloadChecksumsRejectCorruption() throws {
  let root = try temporaryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }

  let source  = root.appendingPathComponent("source", isDirectory: true)
  let archive = root.appendingPathComponent("checksums.zip")
  let sizes   = [49152, 49153, 98304, 98311]
  var payloads: [Data] = []

  try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
  for (index, size) in sizes.enumerated() {
    let data = Data((0..<size).map { UInt8(truncatingIfNeeded: $0 * 17) })
    try data.write(to: source.appendingPathComponent("file-\(index).bin"))
    payloads.append(data)
  }

  try runZip(in: source, archive: archive, omittingDirectories: true)

  for corrupt in [false, true] {
    if corrupt {
      var data = try Data(contentsOf: archive)
      let end = data.count - 22
      try #require(data[end..<(end + 4)].elementsEqual([0x50, 0x4b, 0x05, 0x06]))
      var central = 0
      for index in 0..<4 {
        central |= Int(data[end + 16 + index]) << (index * 8)
      }
      data[central + 16] ^= 1
      try data.write(to: archive, options: .atomic)
    }

    let handle = try #require(archive.withUnsafeFileSystemRepresentation { zipy_open($0) })
    defer { zipy_close(handle) }
    let output = root.appendingPathComponent("output-\(corrupt)")
    var options = zipy_extract_options_t()
    zipy_extract_options_init(&options)
    options.jobs        = 4
    options.on_conflict = ZIPY_CONFLICT_OVERWRITE

    let result = output.withUnsafeFileSystemRepresentation {
      zipy_extract_all(handle, $0, &options)
    }
    #expect(result == (corrupt ? ZIPY_ZIP_ECRC.rawValue : ZIPY_ZIP_OK.rawValue))
    if !corrupt {
      for (index, payload) in payloads.enumerated() {
        #expect(try Data(contentsOf: output.appendingPathComponent("file-\(index).bin")) == payload)
      }
    }
  }
}

@Test
func extractionGrowsSmallOutputBuffers() throws {
  let root = try temporaryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }

  let source  = root.appendingPathComponent("source", isDirectory: true)
  let archive = root.appendingPathComponent("sizes.zip")
  let sizes   = [0, 1, 4095, 4096, 4097, 8192, 262143, 262144, 262145]
  var payloads: [Data] = []

  try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)

  for (index, size) in sizes.enumerated() {
    let data = Data((0..<size).map { UInt8(truncatingIfNeeded: $0 * 31 + index) })
    try data.write(to: source.appendingPathComponent("file-\(index).bin"))
    payloads.append(data)
  }

  try runZip(in: source, archive: archive)

  let handle = try #require(archive.withUnsafeFileSystemRepresentation { zipy_open($0) })
  defer { zipy_close(handle) }

  for jobs in [1, 4] {
    let output = root.appendingPathComponent("output-\(jobs)", isDirectory: true)
    var options = zipy_extract_options_t()
    zipy_extract_options_init(&options)
    options.jobs        = jobs
    options.on_conflict = ZIPY_CONFLICT_OVERWRITE

    let result = output.withUnsafeFileSystemRepresentation {
      zipy_extract_all(handle, $0, &options)
    }
    try #require(result == ZIPY_ZIP_OK.rawValue)

    for (index, payload) in payloads.enumerated() {
      #expect(try Data(contentsOf: output.appendingPathComponent("file-\(index).bin")) == payload)
    }
  }
}

@Test
func unsafeNamesCannotMoveExistingFilesDuringConflictPreparation() throws {
  let root = try temporaryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }

  let source  = root.appendingPathComponent("source", isDirectory: true)
  let archive = root.appendingPathComponent("unsafe.zip")
  let victim  = root.appendingPathComponent("victim.txt")

  let original = Data("keep the original".utf8)
  let name     = Data("xx/victim.txt".utf8)

  try FileManager.default.createDirectory(at: source.appendingPathComponent("xx"),
                                          withIntermediateDirectories: true)
  try Data("archive payload".utf8).write(to: source.appendingPathComponent("xx/victim.txt"))
  try runZip(in: source, archive: archive, omittingDirectories: true)
  let valid = try Data(contentsOf: archive)

  for unsafe in ["../victim.txt", "..\\victim.txt"] {
    var data = valid
    var replacements = 0
    while let range = data.range(of: name) {
      data.replaceSubrange(range, with: Data(unsafe.utf8))
      replacements += 1
    }
    try #require(replacements == 2)
    try data.write(to: archive)

    let handle = try #require(archive.withUnsafeFileSystemRepresentation { zipy_open($0) })
    defer { zipy_close(handle) }
    for mode in 0..<3 {
      let output = root.appendingPathComponent("out-\(unsafe.contains("\\"))-\(mode)")
      try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
      try Data("existing entry".utf8).write(to: output.appendingPathComponent("marker.txt"))
      try original.write(to: victim)
      var options = zipy_extract_options_t()
      zipy_extract_options_init(&options)
      options.jobs = 1

      let result = output.withUnsafeFileSystemRepresentation { destination in
        if mode == 2 {
          return archive.withUnsafeFileSystemRepresentation {
            zipy_extract_stream($0, destination, &options)
          }
        }
        return mode == 1 ? zipy_extract_all(handle, destination, &options)
                         : zipy_extract_to(handle, 0, destination, &options)
      }
      #expect(result == ZIPY_ZIP_EFILE.rawValue)
      #expect((try? Data(contentsOf: victim)) == original)
    }
  }
}

@Test
func parentFileConflictsPreserveSaveSkipAndFailPolicies() throws {
  let root = try temporaryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }

  let source  = root.appendingPathComponent("source", isDirectory: true)
  let archive = root.appendingPathComponent("parents.zip")

  let payload  = Data("nested payload".utf8)
  let original = Data("original parent file".utf8)

  try FileManager.default.createDirectory(at: source.appendingPathComponent("parent/deep"),
                                          withIntermediateDirectories: true)
  try payload.write(to: source.appendingPathComponent("parent/deep/file.txt"))
  try runZip(in: source, archive: archive, omittingDirectories: true)
  let valid = try Data(contentsOf: archive)

  for backslashes in [false, true] {
    var data = valid
    if backslashes {
      let name = Data("parent/deep/file.txt".utf8)
      while let range = data.range(of: name) {
        data.replaceSubrange(range, with: Data("parent\\deep\\file.txt".utf8))
      }
    }
    try data.write(to: archive)
    let handle = try #require(archive.withUnsafeFileSystemRepresentation { zipy_open($0) })
    defer { zipy_close(handle) }

    for policy in [ZIPY_CONFLICT_SAVE, ZIPY_CONFLICT_SKIP, ZIPY_CONFLICT_FAIL] {
      for mode in 0..<3 {
        let output = root.appendingPathComponent("out-\(backslashes)-\(policy.rawValue)-\(mode)")
        try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
        try original.write(to: output.appendingPathComponent("parent"))
        var options = zipy_extract_options_t()
        zipy_extract_options_init(&options)
        options.on_conflict = policy
        options.jobs        = 1

        let result = output.withUnsafeFileSystemRepresentation { destination in
          if mode == 2 {
            return archive.withUnsafeFileSystemRepresentation {
              zipy_extract_stream($0, destination, &options)
            }
          }
          return mode == 1 ? zipy_extract_all(handle, destination, &options)
                           : zipy_extract_to(handle, 0, destination, &options)
        }

        if policy == ZIPY_CONFLICT_SAVE {
          let paths = try FileManager.default.contentsOfDirectory(at: output,
                                                                  includingPropertiesForKeys: nil)
          let saved = try #require(paths.first {
            FileManager.default.fileExists(atPath: $0.appendingPathComponent("zipy_saved_original_paths.txt").path)
          })
          #expect(result >= ZIPY_ZIP_OK.rawValue)
          #expect(try Data(contentsOf: output.appendingPathComponent("parent/deep/file.txt")) == payload)
          #expect(try Data(contentsOf: saved.appendingPathComponent("parent")) == original)
        } else {
          let expected: Int32
          if policy == ZIPY_CONFLICT_FAIL {
            expected = ZIPY_ZIP_EEXIST.rawValue
          } else {
            expected = mode == 0 ? ZIPY_ZIP_SKIPPED.rawValue : ZIPY_ZIP_OK.rawValue
          }
          #expect(result == expected)
          #expect(try Data(contentsOf: output.appendingPathComponent("parent")) == original)
        }
      }
    }
  }
}

@Test
func extractionRejectsLinkedDirectoryParents() throws {
  let root = try temporaryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }

  let source  = root.appendingPathComponent("source", isDirectory: true)
  let nested  = source.appendingPathComponent("link/created", isDirectory: true)
  let outside = root.appendingPathComponent("outside", isDirectory: true)
  let payload = Data("directory boundary".utf8)

  try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
  try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
  try payload.write(to: source.appendingPathComponent("file.txt"))
  try payload.write(to: nested.appendingPathComponent("payload.txt"))
  for preservingLinks in [false, true] {
    if preservingLinks {
      try FileManager.default.createSymbolicLink(
        atPath: source.appendingPathComponent("unrelated-link").path,
        withDestinationPath: "file.txt"
      )
    }

    let archive = root.appendingPathComponent("linked-parent-\(preservingLinks).zip")
    try runZip(in: source, archive: archive, preservingSymlinks: preservingLinks)

    let handle = try #require(archive.withUnsafeFileSystemRepresentation { zipy_open($0) })
    defer { zipy_close(handle) }

    for jobs in [1, 4] {
      let output = root.appendingPathComponent("output-\(preservingLinks)-\(jobs)", isDirectory: true)
      try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
      try FileManager.default.createSymbolicLink(
        atPath: output.appendingPathComponent("link").path,
        withDestinationPath: outside.path
      )

      var options = zipy_extract_options_t()
      zipy_extract_options_init(&options)
      options.jobs        = jobs
      options.on_conflict = ZIPY_CONFLICT_OVERWRITE
      options.flags       = ZIPY_EXTRACT_UNSAFE_SYMLINKS.rawValue

      let result = output.withUnsafeFileSystemRepresentation {
        zipy_extract_all(handle, $0, &options)
      }

      #expect(result == ZIPY_ZIP_EFILE.rawValue)
      #expect(!FileManager.default.fileExists(atPath: outside.appendingPathComponent("created").path))
      #expect(try FileManager.default.contentsOfDirectory(atPath: outside.path).isEmpty)
    }
  }
}

@Test
func extractionCreatesImplicitAndExistingParents() throws {
  let root = try temporaryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }

  let source  = root.appendingPathComponent("source", isDirectory: true)
  let nested  = source.appendingPathComponent("first/second", isDirectory: true)
  let archive = root.appendingPathComponent("implicit.zip")
  let output  = root.appendingPathComponent("output", isDirectory: true)
  let payload = Data("implicit directory payload".utf8)

  try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
  try payload.write(to: nested.appendingPathComponent("file.txt"))
  try runZip(in: source, archive: archive, omittingDirectories: true)

  let handle = try #require(archive.withUnsafeFileSystemRepresentation { zipy_open($0) })
  defer { zipy_close(handle) }

  #expect(zipy_count(handle) == 1)

  for _ in 0..<2 {
    var options = zipy_extract_options_t()
    zipy_extract_options_init(&options)
    options.on_conflict = ZIPY_CONFLICT_OVERWRITE

    let result = output.withUnsafeFileSystemRepresentation {
      zipy_extract_all(handle, $0, &options)
    }

    try #require(result == ZIPY_ZIP_OK.rawValue)
    #expect(try Data(contentsOf: output.appendingPathComponent("first/second/file.txt")) == payload)
  }
}

@Test
func extractionPreservesFileAndDirectoryMetadata() throws {
  let root = try temporaryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }

  let source  = root.appendingPathComponent("source", isDirectory: true)
  let nested  = source.appendingPathComponent("nested", isDirectory: true)
  let archive = root.appendingPathComponent("metadata.zip")

  let payload    = Data("metadata payload".utf8)
  let fileDate   = Date(timeIntervalSince1970: 1_600_000_001)
  let folderDate = Date(timeIntervalSince1970: 1_600_000_000)

  try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
  try payload.write(to: nested.appendingPathComponent("file.txt"))
  try FileManager.default.setAttributes([
    .posixPermissions: 0o640,
    .modificationDate: fileDate
  ], ofItemAtPath: nested.appendingPathComponent("file.txt").path)
  try FileManager.default.setAttributes([
    .posixPermissions: 0o750,
    .modificationDate: folderDate
  ], ofItemAtPath: nested.path)
  try runZip(in: source, archive: archive)

  let handle = try #require(archive.withUnsafeFileSystemRepresentation { zipy_open($0) })
  defer { zipy_close(handle) }

  for jobs in [1, 4] {
    for atomic in [false, true] {
      let output = root.appendingPathComponent("output-\(jobs)-\(atomic)", isDirectory: true)

      var options = zipy_extract_options_t()
      zipy_extract_options_init(&options)
      options.jobs        = jobs
      options.on_conflict = ZIPY_CONFLICT_OVERWRITE
      options.flags       = atomic ? ZIPY_EXTRACT_ATOMIC.rawValue : 0

      let result = output.withUnsafeFileSystemRepresentation {
        zipy_extract_all(handle, $0, &options)
      }
      try #require(result == ZIPY_ZIP_OK.rawValue)

      let folder = output.appendingPathComponent("nested")
      let file   = folder.appendingPathComponent("file.txt")
      let folderAttributes = try FileManager.default.attributesOfItem(atPath: folder.path)
      let fileAttributes   = try FileManager.default.attributesOfItem(atPath: file.path)

      #expect((folderAttributes[.posixPermissions] as? NSNumber)?.intValue == 0o750)
      #expect((fileAttributes[.posixPermissions] as? NSNumber)?.intValue == 0o640)
      #expect(folderAttributes[.modificationDate] as? Date == folderDate)
      #expect(fileAttributes[.modificationDate] as? Date == fileDate)
      #expect(try Data(contentsOf: file) == payload)
    }
  }
}

@Test
func repeatedDOSTimestampsPreserveEntryTimes() throws {
  let root = try temporaryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }

  let source  = root.appendingPathComponent("source", isDirectory: true)
  let archive = root.appendingPathComponent("dos-times.zip")
  let payload = Data("timestamp payload".utf8)
  let seconds = [1_600_000_000, 1_600_000_000, 1_600_000_002,
                 1_600_086_402, 1_600_086_402, 1_600_000_000]
  var expected: [String: Date] = [:]

  try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
  for (index, timestamp) in seconds.enumerated() {
    let name = "file-\(index).txt"
    let file = source.appendingPathComponent(name)
    let date = Date(timeIntervalSince1970: Double(timestamp))
    try payload.write(to: file)
    try FileManager.default.setAttributes([.modificationDate: date], ofItemAtPath: file.path)
    expected[name] = date
  }
  try runZip(in: source, archive: archive, omittingDirectories: true, omittingExtraFields: true)

  let handle = try #require(archive.withUnsafeFileSystemRepresentation { zipy_open($0) })
  defer { zipy_close(handle) }
  #expect(zipy_count(handle) == expected.count)

  for index in 0..<zipy_count(handle) {
    let entry   = try #require(zipy_entry(handle, index))
    let pointer = try #require(entry.pointee.name)
    let name    = URL(fileURLWithPath: String(cString: pointer)).lastPathComponent
    var timestamp: Int64 = 0
    #expect(zipy_entry_mtime(handle, index, &timestamp))
    #expect(Date(timeIntervalSince1970: Double(timestamp)) == expected[name])
  }

  for streaming in [false, true] {
    let output = root.appendingPathComponent("out-\(streaming)")
    let result = output.withUnsafeFileSystemRepresentation { destination in
      if streaming {
        return archive.withUnsafeFileSystemRepresentation { zipy_extract_stream($0, destination, nil) }
      }
      return zipy_extract_all(handle, destination, nil)
    }
    try #require(result == ZIPY_ZIP_OK.rawValue)

    for (name, date) in expected {
      let file  = output.appendingPathComponent(name)
      let attrs = try FileManager.default.attributesOfItem(atPath: file.path)
      #expect(attrs[.modificationDate] as? Date == date)
      #expect(try Data(contentsOf: file) == payload)
    }
  }
}

@Test
func streamedExtendedTimestampsPreserveExactSeconds() throws {
  let root = try temporaryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }

  let source  = root.appendingPathComponent("source", isDirectory: true)
  let archive = root.appendingPathComponent("timestamps.zip")
  let file    = source.appendingPathComponent("file.txt")
  let payload = Data("timestamp payload".utf8)

  try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
  try payload.write(to: file)
  try FileManager.default.setAttributes(
    [.modificationDate: Date(timeIntervalSince1970: 1_600_000_001)], ofItemAtPath: file.path)
  try runZip(in: source, archive: archive, omittingDirectories: true)

  let original = try Data(contentsOf: archive)
  func u16(_ offset: Int) -> Int {
    Int(original[offset]) | Int(original[offset + 1]) << 8
  }

  var position = 30 + u16(26)
  let end = position + u16(28)
  while position + 4 <= end, u16(position) != 0x5455 {
    position += 4 + u16(position + 2)
  }
  try #require(position + 9 <= end)

  for timestamp in [UInt32(0), UInt32(1_600_000_001)] {
    var data  = original
    var value = timestamp.littleEndian
    withUnsafeBytes(of: &value) {
      data.replaceSubrange((position + 5)..<(position + 9), with: $0)
    }
    try data.write(to: archive)

    let output = root.appendingPathComponent("out-\(timestamp)")
    let result = archive.withUnsafeFileSystemRepresentation { input in
      output.withUnsafeFileSystemRepresentation { zipy_extract_stream(input, $0, nil) }
    }
    try #require(result == ZIPY_ZIP_OK.rawValue)

    let extracted = output.appendingPathComponent("file.txt")
    let attributes = try FileManager.default.attributesOfItem(atPath: extracted.path)
    #expect(attributes[.modificationDate] as? Date
              == Date(timeIntervalSince1970: Double(timestamp)))
    #expect(try Data(contentsOf: extracted) == payload)
  }
}

@Test
func deflatedSymlinksReadTheirOwnPayload() throws {
  let root = try temporaryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }

  let source = root.appendingPathComponent("source", isDirectory: true)
  let target = String(repeating: "nested/", count: 24) + "payload.txt"

  try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
  try Data(target.utf8).write(to: source.appendingPathComponent("link"))

  for password in [nil, "secret"] as [String?] {
    let archive = root.appendingPathComponent("link-\(password != nil).zip")
    try runZip(in: source, archive: archive, password: password)

    let original = try Data(contentsOf: archive)
    let central = try #require(original.range(of: Data([0x50, 0x4b, 0x01, 0x02]))).lowerBound

    for corruption in password == nil ? [0, 1, 2] : [0] {
      var data = original
      var mode = UInt32(0o120777 << 16).littleEndian
      withUnsafeBytes(of: &mode) {
        data.replaceSubrange((central + 38)..<(central + 42), with: $0)
      }
      if corruption == 1 {
        data[central + 16] ^= 1
      } else if corruption == 2 {
        data[22] += 1
        data[central + 24] += 1
      }
      try data.write(to: archive)

      let handle = try #require(archive.withUnsafeFileSystemRepresentation { zipy_open($0) })
      defer { zipy_close(handle) }

      let entry = try #require(zipy_entry(handle, 0))
      try #require(entry.pointee.method == 8)

      for all in [false, true] {
        let output = root.appendingPathComponent("out-\(password != nil)-\(corruption)-\(all)")
        try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)

        var options = zipy_extract_options_t()
        zipy_extract_options_init(&options)
        if corruption == 2 { options.flags |= ZIPY_EXTRACT_NO_CRC.rawValue }

        let extract: (UnsafePointer<CChar>?) -> Int32 = { key in
          options.password = key
          return output.withUnsafeFileSystemRepresentation {
            all ? zipy_extract_all(handle, $0, &options)
                : zipy_extract_to(handle, 0, $0, &options)
          }
        }
        let result = password.map { $0.withCString(extract) } ?? extract(nil)

        let expected: Int32
        switch corruption {
        case 1: expected = ZIPY_ZIP_ECRC.rawValue
        case 2: expected = ZIPY_ZIP_ESIZE.rawValue
        default: expected = ZIPY_ZIP_OK.rawValue
        }
        #expect(result == expected)
        let link = output.appendingPathComponent("link")
        if corruption != 0 {
          #expect((try? FileManager.default.destinationOfSymbolicLink(atPath: link.path)) == nil)
        } else {
          #expect(try FileManager.default.destinationOfSymbolicLink(atPath: link.path) == target)
        }
      }
    }
  }
}

@Test
func parallelAtomicExtractionKeepsSharedPartDirectories() throws {
  let root = try temporaryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }

  let source = root.appendingPathComponent("source", isDirectory: true)
  let shared = source.appendingPathComponent("shared/deep", isDirectory: true)
  try FileManager.default.createDirectory(at: shared, withIntermediateDirectories: true)

  let payloads = (0..<512).map { Data(String(repeating: "payload-\($0)\n", count: 512).utf8) }
  for index in payloads.indices {
    try payloads[index].write(to: shared.appendingPathComponent("file-\(index).txt"))
  }

  for stored in [false, true] {
    let archive = root.appendingPathComponent("atomic-\(stored).zip")
    try runZip(in: source, archive: archive, storing: stored)

    let handle = try #require(archive.withUnsafeFileSystemRepresentation { zipy_open($0) })
    defer { zipy_close(handle) }

    for round in 0..<2 {
      let output = root.appendingPathComponent("output-\(stored)-\(round)", isDirectory: true)
      try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)

      var options = zipy_extract_options_t()
      zipy_extract_options_init(&options)
      options.jobs        = 8
      options.flags       = ZIPY_EXTRACT_ATOMIC.rawValue | ZIPY_EXTRACT_NO_METADATA.rawValue
      options.on_conflict = ZIPY_CONFLICT_OVERWRITE

      let result = output.withUnsafeFileSystemRepresentation {
        zipy_extract_all(handle, $0, &options)
      }

      try #require(result == ZIPY_ZIP_OK.rawValue)

      for index in payloads.indices {
        #expect(
          try Data(contentsOf: output.appendingPathComponent("shared/deep/file-\(index).txt"))
            == payloads[index]
        )
      }

      #expect(!FileManager.default.fileExists(atPath: output.appendingPathComponent(".zipy").path))
    }
  }
}

@Test
func atomicCleanupPreservesArchiveZipyDirectory() throws {
  let root = try temporaryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }

  let source = root.appendingPathComponent("source", isDirectory: true)
  let archive = root.appendingPathComponent("cleanup.zip")
  let names = ["top-0", "top-1"] + ["a/deep", "b/deep", "Örnek/deep"].flatMap { parent in
    (0..<16).map { "\(parent)/file-\($0).txt" }
  }

  try FileManager.default.createDirectory(at: source.appendingPathComponent(".zipy"),
                                          withIntermediateDirectories: true)
  for name in names {
    let file = source.appendingPathComponent(name)
    try FileManager.default.createDirectory(at: file.deletingLastPathComponent(),
                                            withIntermediateDirectories: true)
    try Data((name + " payload").utf8).write(to: file)
  }
  try runZip(in: source, archive: archive)

  let handle = try #require(archive.withUnsafeFileSystemRepresentation { zipy_open($0) })
  defer { zipy_close(handle) }

  for jobs in [1, 4] {
    let output = root.appendingPathComponent("output-\(jobs)", isDirectory: true)
    var options = zipy_extract_options_t()
    zipy_extract_options_init(&options)
    options.jobs        = numericCast(jobs)
    options.flags       = ZIPY_EXTRACT_ATOMIC.rawValue
    options.on_conflict = ZIPY_CONFLICT_OVERWRITE

    #expect(output.withUnsafeFileSystemRepresentation {
      zipy_extract_all(handle, $0, &options)
    } == ZIPY_ZIP_OK.rawValue)

    for name in names {
      #expect(try Data(contentsOf: output.appendingPathComponent(name)) == Data((name + " payload").utf8))
    }
    #expect(try FileManager.default.contentsOfDirectory(
      atPath: output.appendingPathComponent(".zipy").path
    ).isEmpty)
  }
}

@Test
func cancelledParallelAtomicExtractionRemovesPartialPayloads() throws {
  let root = try temporaryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }

  let source  = root.appendingPathComponent("source/shared", isDirectory: true)
  let archive = root.appendingPathComponent("cancelled.zip")
  let output  = root.appendingPathComponent("output", isDirectory: true)

  try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
  try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)

  for index in 0..<128 {
    try Data(repeating: UInt8(index), count: 64 * 1024)
      .write(to: source.appendingPathComponent("file-\(index).txt"))
  }

  try runZip(in: source, archive: archive)

  let handle = try #require(archive.withUnsafeFileSystemRepresentation { zipy_open($0) })
  defer { zipy_close(handle) }

  var options = zipy_extract_options_t()
  zipy_extract_options_init(&options)
  options.jobs        = 8
  options.flags       = ZIPY_EXTRACT_ATOMIC.rawValue | ZIPY_EXTRACT_NO_METADATA.rawValue
  options.on_conflict = ZIPY_CONFLICT_OVERWRITE
  options.progress    = { _, _, done, _ in done < 32 * 1024 ? 1 : 0 }

  let result = output.withUnsafeFileSystemRepresentation {
    zipy_extract_all(handle, $0, &options)
  }

  #expect(result == ZIPY_ZIP_ECANCEL.rawValue)

  let contents = try #require(FileManager.default.enumerator(at: output, includingPropertiesForKeys: nil))
  for case let file as URL in contents {
    #expect(!file.lastPathComponent.hasSuffix(".part"))
  }
}

@Test
func indexedModificationTime() throws {
  let root = try temporaryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }

  let source   = root.appendingPathComponent("source", isDirectory: true)
  let archive  = root.appendingPathComponent("archive.zip")
  let file     = source.appendingPathComponent("data.bin")
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
func indexedTimestampFallbackAndEpoch() throws {
  let root = try temporaryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }

  let source  = root.appendingPathComponent("source", isDirectory: true)
  let archive = root.appendingPathComponent("archive.zip")
  let file    = source.appendingPathComponent("data.bin")

  try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
  try Data("payload".utf8).write(to: file)
  try FileManager.default.setAttributes(
    [.modificationDate: Date(timeIntervalSince1970: 1_600_000_001)],
    ofItemAtPath: file.path
  )
  try runZip(in: source, archive: archive)

  let original = try Data(contentsOf: archive)
  let central  = try #require(original.range(of: Data([0x50, 0x4b, 0x01, 0x02]))).lowerBound

  func u16(_ offset: Int) -> Int {
    Int(original[offset]) | Int(original[offset + 1]) << 8
  }

  let date = u16(central + 14)
  let time = u16(central + 12)

  var calendar = Calendar(identifier: .gregorian)
  calendar.timeZone = .current

  let dosDate = try #require(
    calendar.date(from: DateComponents(
      year: 1980 + (date >> 9),
      month: (date >> 5) & 15,
      day: date & 31,
      hour: time >> 11,
      minute: (time >> 5) & 63,
      second: (time & 31) * 2
    ))
  )

  var position = central + 46 + u16(central + 28)
  let end = position + u16(central + 30)

  while position + 4 <= end, u16(position) != 0x5455 {
    position += 4 + u16(position + 2)
  }

  try #require(position + 9 <= end)

  let timestampField = position
  for unixTime in [nil, UInt32(0), UInt32(1_600_000_001)] {
    var bytes = original

    if var value = unixTime?.littleEndian {
      withUnsafeBytes(of: &value) {
        bytes.replaceSubrange((timestampField + 5)..<(timestampField + 9), with: $0)
      }
    } else {
      // an unknown extra field leaves the DOS timestamp as the fallback.
      bytes[timestampField] = 0x56
    }

    try bytes.write(to: archive)

    let handle = try #require(archive.withUnsafeFileSystemRepresentation { zipy_open($0) })
    defer { zipy_close(handle) }

    var timestamp: Int64 = -1
    #expect(zipy_entry_mtime(handle, 0, &timestamp))
    #expect(timestamp == unixTime.map(Int64.init) ?? Int64(dosDate.timeIntervalSince1970))
  }
}

@Test
func indexedExtractionReadsLocalHeaders() throws {
  let root = try temporaryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }

  let source   = root.appendingPathComponent("source", isDirectory: true)
  let contents = Data(repeating: 0x41, count: 4096)

  try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
  try contents.write(to: source.appendingPathComponent("data.bin"))

  for stored in [false, true] {
    let archive = root.appendingPathComponent(stored ? "stored.zip" : "deflated.zip")
    let output  = root.appendingPathComponent(stored ? "stored" : "deflated")

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

  let source  = root.appendingPathComponent("source", isDirectory: true)
  let archive = root.appendingPathComponent("archive.zip")
  let output  = root.appendingPathComponent("output", isDirectory: true)

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
func encryptedExtractionGrowsInputBuffers() throws {
  let root = try temporaryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }

  let source   = root.appendingPathComponent("source", isDirectory: true)
  let password = "zipy-test-password"
  let small    = Data(String(repeating: "small payload\n", count: 200).utf8)
  var large    = Data()
  var block    = [UInt8](repeating: 0, count: 16384)
  var state: UInt32 = 0x31415926

  // adjacent duplicates compress while unique blocks keep the input above 1 MiB.
  for _ in 0..<70 {
    for index in block.indices {
      state ^= state << 13
      state ^= state >> 17
      state ^= state << 5
      block[index] = UInt8(truncatingIfNeeded: state)
    }
    large.append(contentsOf: block)
    large.append(contentsOf: block)
  }

  try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
  try small.write(to: source.appendingPathComponent("small.bin"))
  try large.write(to: source.appendingPathComponent("large.bin"))

  for stored in [false, true] {
    let archive = root.appendingPathComponent("encrypted-\(stored).zip")
    let output  = root.appendingPathComponent("output-\(stored)", isDirectory: true)
    try runZip(in: source, archive: archive, storing: stored, password: password)

    let handle = try #require(archive.withUnsafeFileSystemRepresentation { zipy_open($0) })
    defer { zipy_close(handle) }
    let indices = (0..<zipy_count(handle)).sorted {
      zipy_entry(handle, $0)!.pointee.uncompressed_size < zipy_entry(handle, $1)!.pointee.uncompressed_size
    }
    let last = try #require(indices.last)
    let entry = try #require(zipy_entry(handle, last))
    #expect(entry.pointee.method == (stored ? 0 : 8))
    #expect(entry.pointee.compressed_size > 1024 * 1024)

    var options = zipy_extract_options_t()
    zipy_extract_options_init(&options)
    options.on_conflict = ZIPY_CONFLICT_OVERWRITE

    try password.withCString { passwordC in
      options.password = passwordC
      for index in indices {
        let result = output.withUnsafeFileSystemRepresentation {
          zipy_extract_to(handle, index, $0, &options)
        }
        try #require(result == ZIPY_ZIP_OK.rawValue)
      }
    }

    #expect(try Data(contentsOf: output.appendingPathComponent("small.bin")) == small)
    #expect(try Data(contentsOf: output.appendingPathComponent("large.bin")) == large)
  }
}

@Test
func encryptedSymlinkExtracts() throws {
  let root = try temporaryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }

  let source   = root.appendingPathComponent("source", isDirectory: true)
  let payload  = Data(String(repeating: "encrypted payload\n", count: 128).utf8)
  let password = "zipy-test-password"

  try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
  try payload.write(to: source.appendingPathComponent("file.txt"))
  try FileManager.default.createSymbolicLink(
    atPath: source.appendingPathComponent("link").path,
    withDestinationPath: "file.txt"
  )

  for stored in [false, true] {
    let archive = root.appendingPathComponent("encrypted-\(stored).zip")
    let output  = root.appendingPathComponent("output-\(stored)", isDirectory: true)

    try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
    try runZip(
      in: source,
      archive: archive,
      preservingSymlinks: true,
      storing: stored,
      password: password
    )

    let handle = try #require(archive.withUnsafeFileSystemRepresentation { zipy_open($0) })
    defer { zipy_close(handle) }

    var options = zipy_extract_options_t()
    zipy_extract_options_init(&options)
    options.jobs        = 2
    options.on_conflict = ZIPY_CONFLICT_OVERWRITE

    let result = password.withCString { passwordC in
      options.password = passwordC
      return output.withUnsafeFileSystemRepresentation {
        zipy_extract_all(handle, $0, &options)
      }
    }

    try #require(result == ZIPY_ZIP_OK.rawValue)

    let link = output.appendingPathComponent("link")
    #expect(try FileManager.default.destinationOfSymbolicLink(atPath: link.path) == "file.txt")
    #expect(try Data(contentsOf: link) == payload)
  }
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
  storing: Bool = false,
  password: String? = nil,
  omittingDirectories: Bool = false,
  omittingExtraFields: Bool = false
) throws {
  let process = Process()
  process.executableURL       = URL(fileURLWithPath: "/usr/bin/zip")
  process.currentDirectoryURL = directory
  process.arguments = preservingSymlinks
    ? ["-qry", archive.path, "."]
    : ["-qr", archive.path, "."]

  if storing {
    process.arguments?.insert("-0", at: 0)
  }

  if let password {
    process.arguments?.insert(contentsOf: ["-P", password], at: 0)
  }

  if omittingDirectories {
    process.arguments?.insert("-D", at: 0)
  }

  if omittingExtraFields {
    process.arguments?.insert("-X", at: 0)
  }

  try process.run()
  process.waitUntilExit()

  if process.terminationStatus != 0 {
    throw ZipTestError.zipFailed(process.terminationStatus)
  }
}

private enum ZipTestError: Error {
  case zipFailed(Int32)
}
