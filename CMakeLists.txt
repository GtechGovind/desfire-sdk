cmake_minimum_required(VERSION 3.25)

project(desfire-sdk VERSION 0.1.0 LANGUAGES C CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

option(DESFIRE_BUILD_TESTS "Build deterministic host-side tests" ON)
option(DESFIRE_BUILD_PCSC "Build the optional desktop PC/SC transport" ON)
option(DESFIRE_BUILD_OPENSSL "Build the OpenSSL cryptographic provider" ON)
option(DESFIRE_BUILD_C_API "Build the stable C99 ABI" ON)
option(DESFIRE_BUILD_FUZZERS "Build libFuzzer parser target" OFF)
option(DESFIRE_BUILD_JNI "Build Kotlin/JVM JNI bridge" OFF)
option(DESFIRE_BUILD_CPP17 "Build the strict C++17 facade" ON)
option(DESFIRE_BUILD_EXAMPLES "Build compiled C and C++17 examples" ON)
option(DESFIRE_BUILD_CODSPEED_BENCHMARKS
    "Build the opt-in CodSpeed Google Benchmark executable" OFF)

set(DESFIRE_CXX_STANDARD 26 CACHE STRING "C++ language mode for the SDK (23 or 26)")
set_property(CACHE DESFIRE_CXX_STANDARD PROPERTY STRINGS 23 26)
if(NOT DESFIRE_CXX_STANDARD MATCHES "^(23|26)$")
    message(FATAL_ERROR "DESFIRE_CXX_STANDARD must be 23 or 26")
endif()
# Some supported compiler/CMake pairs implement C++26 without advertising CMake's
# cxx_std_26 feature. Probe the compiler before supplying only the missing metadata.
if(DESFIRE_CXX_STANDARD EQUAL 26
   AND NOT "cxx_std_26" IN_LIST CMAKE_CXX_COMPILE_FEATURES)
    include(CheckCXXCompilerFlag)
    if(MSVC)
        set(_desfire_cxx26_candidates "/std:c++latest")
    else()
        set(_desfire_cxx26_candidates "-std=c++26" "-std=c++2c")
    endif()
    unset(_desfire_cxx26_flag)
    foreach(_desfire_candidate IN LISTS _desfire_cxx26_candidates)
        string(MAKE_C_IDENTIFIER "${_desfire_candidate}" _desfire_candidate_id)
        set(_desfire_probe "DESFIRE_COMPILER_HAS_CXX26_${_desfire_candidate_id}")
        check_cxx_compiler_flag("${_desfire_candidate}" "${_desfire_probe}")
        if(${_desfire_probe})
            set(_desfire_cxx26_flag "${_desfire_candidate}")
            break()
        endif()
    endforeach()
    if(NOT _desfire_cxx26_flag)
        message(FATAL_ERROR "C++26 is unavailable; select -DDESFIRE_CXX_STANDARD=23")
    endif()
    set(CMAKE_CXX26_STANDARD_COMPILE_OPTION "${_desfire_cxx26_flag}")
    set(CMAKE_CXX26_EXTENSION_COMPILE_OPTION "${_desfire_cxx26_flag}")
    set(CMAKE_CXX26_STANDARD__HAS_FULL_SUPPORT TRUE)
    list(APPEND CMAKE_CXX_COMPILE_FEATURES cxx_std_26)
endif()
set(CMAKE_CXX_STANDARD ${DESFIRE_CXX_STANDARD})
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(DesfireSanitizers)
include(DesfireTargetPolicy)

add_subdirectory(foundation)
add_subdirectory(core)
add_subdirectory(transports/callback)
add_subdirectory(transports/replay)

if(DESFIRE_BUILD_OPENSSL)
    add_subdirectory(providers/crypto-openssl)
endif()

if(DESFIRE_BUILD_PCSC)
    add_subdirectory(transports/pcsc)
endif()

if(DESFIRE_BUILD_C_API)
    if(NOT DESFIRE_BUILD_OPENSSL)
        message(FATAL_ERROR "The C ABI currently requires DESFIRE_BUILD_OPENSSL")
    endif()
    add_subdirectory(c-api)
    if(DESFIRE_BUILD_CPP17)
        add_subdirectory(sdk/cpp17)
    endif()
endif()

if(DESFIRE_BUILD_JNI)
    if(NOT DESFIRE_BUILD_C_API)
        message(FATAL_ERROR "JNI requires the C ABI")
    endif()
    add_subdirectory(sdk/kotlin)
endif()

if(DESFIRE_BUILD_CODSPEED_BENCHMARKS)
    if(NOT DESFIRE_BUILD_TESTS)
        message(FATAL_ERROR "CodSpeed benchmarks require DESFIRE_BUILD_TESTS=ON")
    endif()
    if(NOT DESFIRE_BUILD_OPENSSL)
        message(FATAL_ERROR "CodSpeed benchmarks require DESFIRE_BUILD_OPENSSL=ON")
    endif()
    include(DesfireCodSpeed)
endif()

if(DESFIRE_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(DESFIRE_BUILD_EXAMPLES AND DESFIRE_BUILD_C_API)
    add_subdirectory(examples)
endif()

include(DesfireDocumentation)

configure_package_config_file(
    cmake/PackageConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/desfire-sdk-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/desfire-sdk)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/desfire-sdk-config-version.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion)
install(EXPORT desfireTargets
    FILE desfire-sdk-targets.cmake
    NAMESPACE desfire::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/desfire-sdk)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/desfire-sdk-config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/desfire-sdk-config-version.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/desfire-sdk)

install(FILES LICENSE NOTICE DESTINATION ${CMAKE_INSTALL_DATADIR}/desfire-sdk)
