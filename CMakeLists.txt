cmake_minimum_required(VERSION 3.13)
project(zap
  VERSION 0.1.0
  HOMEPAGE_URL https://github.com/recp/zap
  DESCRIPTION "minimal ZIP archive library"
  LANGUAGES C
)

set(CMAKE_C_STANDARD 11)

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

find_package(ZLIB REQUIRED)

include_directories(include)

option(ZAP_BUILD_EXECUTABLE "Build zap command line tool" OFF)

add_library(${PROJECT_NAME}
        src/zip.c
)

set_target_properties(${PROJECT_NAME} PROPERTIES
                              VERSION ${PROJECT_VERSION} 
                            SOVERSION ${PROJECT_VERSION_MAJOR})

if(WIN32)
  # Because SOVERSION has no effect to file naming on Windows
  set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_NAME ${PROJECT_NAME}-${PROJECT_VERSION_MAJOR})
endif()

target_include_directories(zap
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(zap
    PUBLIC
        ZLIB::ZLIB
)

# Executable target
if(ZAP_BUILD_EXECUTABLE)
    add_executable(zap-bin
        src/main.c
    )
    
    set_target_properties(zap-bin 
        PROPERTIES 
        OUTPUT_NAME "zap"
    )
    
    target_link_libraries(zap-bin
        PRIVATE
            zap
    )
endif()

install(TARGETS zap
        EXPORT zapTargets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if(ZAP_BUILD_EXECUTABLE)
    install(TARGETS zap-bin
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()

install(DIRECTORY include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Package config
install(EXPORT zapTargets
        FILE zapTargets.cmake
        NAMESPACE zap::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/zap
)

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "zapConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/zapConfigVersion.cmake"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/zap
)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})

if(NOT CPack_CMake_INCLUDED)
  include(CPack)
endif()
