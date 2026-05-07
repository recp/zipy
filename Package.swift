// swift-tools-version: 6.0

import PackageDescription

let package = Package(
  name: "zipy",
  platforms: [
    .iOS(.v13),
    .macOS(.v10_15),
    .tvOS(.v13),
    .watchOS(.v6)
  ],
  products: [
    .library(name: "Zipy", targets: ["Zipy"]),
    .library(name: "CZipy", targets: ["CZipy"])
  ],
  targets: [
    .target(
      name: "CZipy",
      path: ".",
      exclude: [
        ".build",
        ".git",
        ".vscode",
        "build",
        "cmake",
        "cmake-build-debug",
        "swift",
        "CMakeLists.txt",
        "LICENSE",
        "README.md"
      ],
      sources: [
        "src/zip.c",
        "src/crypto/dec.c",
        "src/crypto/aes_wg.c",
        "src/crypto/sha1.c",
        "src/posix/thread.c",
        "deps/defl/src/infl/infl.c",
        "deps/defl/src/infl/stream.c",
        "deps/defl/src/infl/mem.c"
      ],
      publicHeadersPath: "include",
      cSettings: [
        .define("ZIPY_STATIC", to: "1"),
        .define("ZIPY_EXPORTS", to: "1"),
        .define("UNZ_STATIC", to: "1"),
        .define("UNZ_EXPORTS", to: "1"),
        .headerSearchPath("src"),
        .headerSearchPath("deps/defl/include"),
        .headerSearchPath("deps/huff/include")
      ],
      linkerSettings: [
        .linkedLibrary("pthread", .when(platforms: [.linux]))
      ]
    ),
    .target(
      name: "Zipy",
      dependencies: ["CZipy"],
      path: "swift/Sources/Zipy"
    ),
    .testTarget(
      name: "ZipyTests",
      dependencies: ["Zipy"],
      path: "swift/Tests/ZipyTests"
    )
  ]
)
