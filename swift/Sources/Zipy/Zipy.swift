import CZipy
import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

public enum Zipy {
  public struct ExtractOptions: OptionSet, Sendable {
    public let rawValue: UInt32

    public init(rawValue: UInt32) {
      self.rawValue = rawValue
    }

    public static let noCRC = Self(rawValue: 1 << 0)
    public static let noMetadata = Self(rawValue: 1 << 1)
    public static let atomic = Self(rawValue: 1 << 2)
    public static let resume = Self(rawValue: 1 << 3)
    public static let fast: Self = [.noCRC, .noMetadata]
  }

  public enum ConflictPolicy: Sendable {
    case save
    case overwrite
    case skip
    case fail

    fileprivate var cValue: zipy_conflict_policy_t {
      switch self {
      case .save:
        return zipy_conflict_policy_t(rawValue: 0)
      case .overwrite:
        return zipy_conflict_policy_t(rawValue: 1)
      case .skip:
        return zipy_conflict_policy_t(rawValue: 2)
      case .fail:
        return zipy_conflict_policy_t(rawValue: 3)
      }
    }
  }

  public enum SaveLocation: Sendable {
    case target
    case home
    case trash

    fileprivate var cValue: zipy_save_location_t {
      switch self {
      case .target:
        return zipy_save_location_t(rawValue: 0)
      case .home:
        return zipy_save_location_t(rawValue: 1)
      case .trash:
        return zipy_save_location_t(rawValue: 2)
      }
    }
  }

  public struct ExtractProgress: Sendable {
    public let entryName: String?
    public let completedBytes: UInt64
    public let totalBytes: UInt64

    public var fractionCompleted: Double? {
      guard totalBytes > 0 else {
        return nil
      }
      return min(1.0, Double(completedBytes) / Double(totalBytes))
    }
  }

  public enum Error: Swift.Error, CustomStringConvertible, Sendable {
    case openFailed(String)
    case invalidArgument(String)
    case operationFailed(code: Int32, message: String)

    public var description: String {
      switch self {
      case .openFailed(let path):
        return "cannot open zip archive: \(path)"
      case .invalidArgument(let message):
        return message
      case .operationFailed(let code, let message):
        return "\(message) (\(code))"
      }
    }
  }

  public typealias ProgressHandler = @Sendable (ExtractProgress) -> Bool

  public static func extract(
    _ archive: URL,
    to destination: URL,
    options: ExtractOptions = [],
    conflict: ConflictPolicy = .save,
    saveTo: SaveLocation = .target,
    password: String? = nil,
    jobs: Int = 0,
    progress: Progress? = nil,
    observer: ZipyProgressActor? = nil,
    priority: TaskPriority? = nil,
    onProgress: ProgressHandler? = nil
  ) async throws {
    let sendableProgress = SendableProgress(progress)
    let archivePath = canonicalPath(archive)
    let destinationPath = canonicalPath(destination)

    try await Task.detached(priority: priority) {
      try extractSync(
        archivePath,
        to: destinationPath,
        options: options,
        conflict: conflict,
        saveTo: saveTo,
        password: password,
        jobs: jobs,
        progress: sendableProgress.value,
        observer: observer,
        onProgress: onProgress
      )
    }.value
  }

  public static func extract(
    _ archivePath: String,
    to destinationPath: String,
    options: ExtractOptions = [],
    conflict: ConflictPolicy = .save,
    saveTo: SaveLocation = .target,
    password: String? = nil,
    jobs: Int = 0,
    progress: Progress? = nil,
    observer: ZipyProgressActor? = nil,
    priority: TaskPriority? = nil,
    onProgress: ProgressHandler? = nil
  ) async throws {
    let sendableProgress = SendableProgress(progress)

    try await Task.detached(priority: priority) {
      try extractSync(
        archivePath,
        to: destinationPath,
        options: options,
        conflict: conflict,
        saveTo: saveTo,
        password: password,
        jobs: jobs,
        progress: sendableProgress.value,
        observer: observer,
        onProgress: onProgress
      )
    }.value
  }

  public static func extractSync(
    _ archive: URL,
    to destination: URL,
    options: ExtractOptions = [],
    conflict: ConflictPolicy = .save,
    saveTo: SaveLocation = .target,
    password: String? = nil,
    jobs: Int = 0,
    progress: Progress? = nil,
    observer: ZipyProgressActor? = nil,
    onProgress: ProgressHandler? = nil
  ) throws {
    try extractSync(
      canonicalPath(archive),
      to: canonicalPath(destination),
      options: options,
      conflict: conflict,
      saveTo: saveTo,
      password: password,
      jobs: jobs,
      progress: progress,
      observer: observer,
      onProgress: onProgress
    )
  }

  public static func extractSync(
    _ archivePath: String,
    to destinationPath: String,
    options: ExtractOptions = [],
    conflict: ConflictPolicy = .save,
    saveTo: SaveLocation = .target,
    password: String? = nil,
    jobs: Int = 0,
    progress: Progress? = nil,
    observer: ZipyProgressActor? = nil,
    onProgress: ProgressHandler? = nil
  ) throws {
    guard jobs >= 0 else {
      throw Error.invalidArgument("jobs must be non-negative")
    }

    let retained = makeProgressContext(
      progress: progress,
      observer: observer,
      handler: onProgress
    )
    defer {
      retained?.release()
    }

    let ret: Int32 = try archivePath.withCString { archiveC in
      try destinationPath.withCString { destinationC in
        try withPasswordCString(password) { passwordC in
          var cOptions = zipy_extract_options_t()
          zipy_extract_options_init(&cOptions)
          cOptions.flags = options.rawValue
          cOptions.on_conflict = conflict.cValue
          cOptions.save_to = saveTo.cValue
          cOptions.password = passwordC
          cOptions.jobs = jobs
          if let retained {
            cOptions.progress = zipyProgressTrampoline
            cOptions.userdata = retained.toOpaque()
          }

          guard let zip = zipy_open(archiveC) else {
            throw Error.openFailed(archivePath)
          }
          defer {
            zipy_close(zip)
          }

          return zipy_extract_all(zip, destinationC, &cOptions)
        }
      }
    }

    try check(ret)
  }

  public static func extractStream(
    _ archive: URL,
    to destination: URL,
    options: ExtractOptions = [],
    conflict: ConflictPolicy = .save,
    saveTo: SaveLocation = .target,
    password: String? = nil,
    jobs: Int = 0,
    progress: Progress? = nil,
    observer: ZipyProgressActor? = nil,
    priority: TaskPriority? = nil,
    onProgress: ProgressHandler? = nil
  ) async throws {
    let sendableProgress = SendableProgress(progress)
    let archivePath = canonicalPath(archive)
    let destinationPath = canonicalPath(destination)

    try await Task.detached(priority: priority) {
      try extractStreamSync(
        archivePath,
        to: destinationPath,
        options: options,
        conflict: conflict,
        saveTo: saveTo,
        password: password,
        jobs: jobs,
        progress: sendableProgress.value,
        observer: observer,
        onProgress: onProgress
      )
    }.value
  }

  public static func extractStream(
    _ archivePath: String,
    to destinationPath: String,
    options: ExtractOptions = [],
    conflict: ConflictPolicy = .save,
    saveTo: SaveLocation = .target,
    password: String? = nil,
    jobs: Int = 0,
    progress: Progress? = nil,
    observer: ZipyProgressActor? = nil,
    priority: TaskPriority? = nil,
    onProgress: ProgressHandler? = nil
  ) async throws {
    let sendableProgress = SendableProgress(progress)

    try await Task.detached(priority: priority) {
      try extractStreamSync(
        archivePath,
        to: destinationPath,
        options: options,
        conflict: conflict,
        saveTo: saveTo,
        password: password,
        jobs: jobs,
        progress: sendableProgress.value,
        observer: observer,
        onProgress: onProgress
      )
    }.value
  }

  public static func extractStreamSync(
    _ archive: URL,
    to destination: URL,
    options: ExtractOptions = [],
    conflict: ConflictPolicy = .save,
    saveTo: SaveLocation = .target,
    password: String? = nil,
    jobs: Int = 0,
    progress: Progress? = nil,
    observer: ZipyProgressActor? = nil,
    onProgress: ProgressHandler? = nil
  ) throws {
    try extractStreamSync(
      canonicalPath(archive),
      to: canonicalPath(destination),
      options: options,
      conflict: conflict,
      saveTo: saveTo,
      password: password,
      jobs: jobs,
      progress: progress,
      observer: observer,
      onProgress: onProgress
    )
  }

  public static func extractStreamSync(
    _ archivePath: String,
    to destinationPath: String,
    options: ExtractOptions = [],
    conflict: ConflictPolicy = .save,
    saveTo: SaveLocation = .target,
    password: String? = nil,
    jobs: Int = 0,
    progress: Progress? = nil,
    observer: ZipyProgressActor? = nil,
    onProgress: ProgressHandler? = nil
  ) throws {
    guard jobs >= 0 else {
      throw Error.invalidArgument("jobs must be non-negative")
    }

    let retained = makeProgressContext(
      progress: progress,
      observer: observer,
      handler: onProgress
    )
    defer {
      retained?.release()
    }

    let ret: Int32 = archivePath.withCString { archiveC in
      destinationPath.withCString { destinationC in
        withPasswordCString(password) { passwordC in
          var cOptions = zipy_extract_options_t()
          zipy_extract_options_init(&cOptions)
          cOptions.flags = options.rawValue
          cOptions.on_conflict = conflict.cValue
          cOptions.save_to = saveTo.cValue
          cOptions.password = passwordC
          cOptions.jobs = jobs
          if let retained {
            cOptions.progress = zipyProgressTrampoline
            cOptions.userdata = retained.toOpaque()
          }

          return zipy_extract_stream(archiveC, destinationC, &cOptions)
        }
      }
    }

    try check(ret)
  }

  private static func check(_ result: Int32) throws {
    guard result < 0 else {
      return
    }

    let message = zipy_strerror(result).map(String.init(cString:)) ?? "zipy error"
    throw Error.operationFailed(code: result, message: message)
  }
}

public actor ZipyProgressActor {
  public private(set) var latest: Zipy.ExtractProgress?

  public init() {}

  fileprivate func update(_ progress: Zipy.ExtractProgress) {
    latest = progress
  }
}

private struct SendableProgress: @unchecked Sendable {
  let value: Progress?

  init(_ value: Progress?) {
    self.value = value
  }
}

private final class ProgressContext: @unchecked Sendable {
  private let progress: Progress?
  private let observer: ZipyProgressActor?
  private let handler: Zipy.ProgressHandler?
  private let lock = NSLock()

  init(
    progress: Progress?,
    observer: ZipyProgressActor?,
    handler: Zipy.ProgressHandler?
  ) {
    self.progress = progress
    self.observer = observer
    self.handler = handler
  }

  func update(entry: UnsafePointer<zipy_entry_t>?, done: UInt64, total: UInt64) -> Int32 {
    let state = Zipy.ExtractProgress(
      entryName: entryName(entry),
      completedBytes: done,
      totalBytes: total
    )

    if let observer {
      Task {
        await observer.update(state)
      }
    }

    lock.lock()
    if let progress {
      if total > 0 {
        progress.totalUnitCount = clampedInt64(total)
      }
      progress.completedUnitCount = clampedInt64(done)
      if progress.isCancelled {
        lock.unlock()
        return 0
      }
    }
    lock.unlock()

    if Task.isCancelled {
      return 0
    }
    if let handler, !handler(state) {
      return 0
    }

    return 1
  }

  private func entryName(_ entry: UnsafePointer<zipy_entry_t>?) -> String? {
    guard let name = entry?.pointee.name else {
      return nil
    }
    return String(cString: name)
  }

  private func clampedInt64(_ value: UInt64) -> Int64 {
    value > UInt64(Int64.max) ? Int64.max : Int64(value)
  }
}

private func makeProgressContext(
  progress: Progress?,
  observer: ZipyProgressActor?,
  handler: Zipy.ProgressHandler?
) -> Unmanaged<ProgressContext>? {
  guard progress != nil || observer != nil || handler != nil else {
    return nil
  }
  return Unmanaged.passRetained(
    ProgressContext(
      progress: progress,
      observer: observer,
      handler: handler
    )
  )
}

private func zipyProgressTrampoline(
  _ userdata: UnsafeMutableRawPointer?,
  _ entry: UnsafePointer<zipy_entry_t>?,
  _ done: UInt64,
  _ total: UInt64
) -> Int32 {
  guard let userdata else {
    return 1
  }
  let context = Unmanaged<ProgressContext>.fromOpaque(userdata).takeUnretainedValue()
  return context.update(entry: entry, done: done, total: total)
}

private func withPasswordCString<R>(
  _ password: String?,
  _ body: (UnsafePointer<CChar>?) throws -> R
) rethrows -> R {
  guard let password else {
    return try body(nil)
  }

  return try password.withCString(body)
}

private func canonicalPath(_ url: URL) -> String {
  var path = url.path
  if let resolved = realpath(path, nil) {
    defer {
      free(resolved)
    }
    return String(cString: resolved)
  }

  var suffixes: [String] = []
  while path != "/" && !path.isEmpty {
    suffixes.append((path as NSString).lastPathComponent)
    path = (path as NSString).deletingLastPathComponent

    if let resolved = realpath(path, nil) {
      var result = String(cString: resolved)
      free(resolved)

      for component in suffixes.reversed() {
        result = (result as NSString).appendingPathComponent(component)
      }
      return result
    }
  }

  return url.resolvingSymlinksInPath().path
}
