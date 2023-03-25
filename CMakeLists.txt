cmake_minimum_required(VERSION 3.24)
project(unzip C)

set(CMAKE_C_STANDARD 11)

include_directories(include)

add_executable(unzip
        include/unzip/common.h
        include/unzip/unzip.h
        src/infl/huff.c
        src/infl/huff.h
        src/infl/infl.c
        src/infl/infl.h
        src/infl/lz77.h
        src/zlib/zlib.h
        src/common.h
        src/endian.h
        src/unzip.c)
