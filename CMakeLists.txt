cmake_minimum_required(VERSION 3.13)
project(zipy
  VERSION 0.1.0
  HOMEPAGE_URL https://github.com/recp/zipy
  DESCRIPTION "minimal ZIP archive library"
  LANGUAGES C
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(DEFAULT_BUILD_TYPE Release)

if(MSVC)
  add_definitions(-D_WINDOWS -D_USRDLL)

  if(NOT CMAKE_BUILD_TYPE MATCHES Debug)
    add_definitions(-DNDEBUG)
    add_compile_options(/W3 /Ox /Gy /Oi /TC)
    foreach(flag_var
        CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
        CMAKE_C_FLAGS_MINSIZEREL CMAKE_C_FLAGS_RELWITHDEBINFO)
      string(REGEX REPLACE "/RTC(su|[1su])" "" ${flag_var} "${${flag_var}}")
    endforeach(flag_var)
  endif()
else()
  add_compile_options(-Wall)

  if(NOT CMAKE_BUILD_TYPE MATCHES Debug)
    add_compile_options(-O3)
  endif()
endif()

get_directory_property(hasParent PARENT_DIRECTORY)

if(NOT hasParent AND NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to '${DEFAULT_BUILD_TYPE}' as none was specified.")
  set(CMAKE_BUILD_TYPE "${DEFAULT_BUILD_TYPE}" CACHE STRING "Choose the type of build." FORCE)
  # Set the possible values of build type for cmake-gui
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

include(GNUInstallDirs)

if(POLICY CMP0002)
  cmake_policy(SET CMP0002 NEW)
endif()

include_directories(include)

option(ZIPY_BUILD_EXECUTABLE "Build zipy command line tool" ON)

if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/deps/defl/include/defl/infl.h"
   OR NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/deps/huff/include/huff/huff.h")
  message(FATAL_ERROR "Missing submodules. Run: git submodule update --init")
endif()

if(WIN32)
    set(ZIPY_THREAD_SOURCE src/win/thread.c)
else()
    set(ZIPY_THREAD_SOURCE src/posix/thread.c)
    find_package(Threads REQUIRED)
endif()

add_library(${PROJECT_NAME}
        src/zip.c
        src/crypto/dec.c
        src/crypto/aes_wg.c
        src/crypto/sha1.c
        ${ZIPY_THREAD_SOURCE}
        deps/defl/src/infl/infl.c
        deps/defl/src/infl/stream.c
        deps/defl/src/infl/mem.c
)

set_target_properties(${PROJECT_NAME} PROPERTIES
                              VERSION ${PROJECT_VERSION} 
                            SOVERSION ${PROJECT_VERSION_MAJOR})

if(WIN32)
  # Because SOVERSION has no effect to file naming on Windows
  set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_NAME ${PROJECT_NAME}-${PROJECT_VERSION_MAJOR})
endif()

target_include_directories(zipy
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/defl/include
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/huff/include
)

target_compile_definitions(zipy
    PRIVATE
        ZIPY_STATIC=1
        ZIPY_EXPORTS=1
        UNZ_STATIC=1
        UNZ_EXPORTS=1
)

if(NOT WIN32)
    target_link_libraries(zipy
        PUBLIC
            Threads::Threads
    )
endif()

# Executable target
if(ZIPY_BUILD_EXECUTABLE)
    add_executable(zipy-bin
        src/main.c
    )
    
    set_target_properties(zipy-bin
        PROPERTIES 
        OUTPUT_NAME "zipy"
    )
    
    target_link_libraries(zipy-bin
        PRIVATE
            zipy
    )

    target_include_directories(zipy-bin
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src
    )

endif()

install(TARGETS zipy
        EXPORT zipyTargets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if(ZIPY_BUILD_EXECUTABLE)
    install(TARGETS zipy-bin
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()

install(DIRECTORY include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Package config
install(EXPORT zipyTargets
        FILE zipyTargets.cmake
        NAMESPACE zipy::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/zipy
)

include(CMakePackageConfigHelpers)
configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/zipyConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/zipyConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/zipy
)

write_basic_package_version_file(
    "zipyConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/zipyConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/zipyConfigVersion.cmake"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/zipy
)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})

if(NOT CPack_CMake_INCLUDED)
  include(CPack)
endif()
