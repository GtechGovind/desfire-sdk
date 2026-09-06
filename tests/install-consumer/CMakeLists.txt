cmake_minimum_required(VERSION 3.25)
project(desfire_install_consumer LANGUAGES C CXX)

set(DESFIRE_INSTALL_CONSUMER_CXX_STANDARD 23 CACHE STRING
    "Language mode used to compile the installed modern-core consumer (23 or 26)")
set_property(CACHE DESFIRE_INSTALL_CONSUMER_CXX_STANDARD PROPERTY STRINGS 23 26)
if(NOT DESFIRE_INSTALL_CONSUMER_CXX_STANDARD MATCHES "^(23|26)$")
    message(FATAL_ERROR "DESFIRE_INSTALL_CONSUMER_CXX_STANDARD must be 23 or 26")
endif()

# Older CMake releases do not know cxx_std_26 even when the compiler implements it.
# Probe the exact mode and provide only the missing metadata; never downgrade silently.
if(DESFIRE_INSTALL_CONSUMER_CXX_STANDARD EQUAL 26
   AND NOT "cxx_std_26" IN_LIST CMAKE_CXX_COMPILE_FEATURES)
    include(CheckCXXCompilerFlag)
    if(MSVC)
        set(_desfire_consumer_cxx26_flag "/std:c++latest")
    else()
        set(_desfire_consumer_cxx26_flag "-std=c++26")
    endif()
    check_cxx_compiler_flag("${_desfire_consumer_cxx26_flag}"
                            DESFIRE_INSTALL_CONSUMER_HAS_CXX26)
    if(NOT DESFIRE_INSTALL_CONSUMER_HAS_CXX26)
        message(FATAL_ERROR "The install consumer requires an available C++26 mode")
    endif()
endif()

find_package(desfire-sdk CONFIG REQUIRED)

add_executable(modern_core_consumer modern_core_consumer.cpp)
if(DESFIRE_INSTALL_CONSUMER_CXX_STANDARD EQUAL 26
   AND DEFINED _desfire_consumer_cxx26_flag)
    target_compile_options(modern_core_consumer PRIVATE "${_desfire_consumer_cxx26_flag}")
else()
    target_compile_features(modern_core_consumer PRIVATE
        cxx_std_${DESFIRE_INSTALL_CONSUMER_CXX_STANDARD})
endif()
target_link_libraries(modern_core_consumer PRIVATE desfire::ev3_core)

# Core-only packages intentionally omit the versioned C ABI and its C++17 facade.
# A full package adds these two consumers without changing their language modes.
if(TARGET desfire::c)
    add_executable(c_consumer ../unit/c_abi_test.c)
    set_target_properties(c_consumer PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED YES)
    file(READ "${CMAKE_CURRENT_LIST_DIR}/../../api/ev3-api.sha256"
        DESFIRE_INSTALL_EXPECTED_MANIFEST_SHA256)
    string(STRIP "${DESFIRE_INSTALL_EXPECTED_MANIFEST_SHA256}"
        DESFIRE_INSTALL_EXPECTED_MANIFEST_SHA256)
    target_compile_definitions(c_consumer PRIVATE
        DESFIRE_EXPECTED_MANIFEST_SHA256="${DESFIRE_INSTALL_EXPECTED_MANIFEST_SHA256}")
    target_link_libraries(c_consumer PRIVATE desfire::c)
endif()

if(TARGET desfire::cpp17)
    add_executable(cpp17_consumer ../unit/cpp17_test.cpp)
    set_target_properties(cpp17_consumer PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS NO)
    target_link_libraries(cpp17_consumer PRIVATE desfire::cpp17)

    add_executable(cpp17_no_exceptions_consumer ../unit/cpp17_test.cpp)
    set_target_properties(cpp17_no_exceptions_consumer PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS NO)
    target_link_libraries(cpp17_no_exceptions_consumer PRIVATE desfire::cpp17)
    if(MSVC)
        target_compile_options(cpp17_no_exceptions_consumer PRIVATE /EHs-c-)
    else()
        target_compile_options(cpp17_no_exceptions_consumer PRIVATE -fno-exceptions)
    endif()

    add_executable(cpp17_throwing_consumer ../unit/cpp17_throwing_test.cpp)
    set_target_properties(cpp17_throwing_consumer PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS NO)
    target_link_libraries(cpp17_throwing_consumer PRIVATE desfire::cpp17)
endif()

enable_testing()
add_test(NAME modern_core_consumer COMMAND modern_core_consumer)
if(TARGET c_consumer)
    add_test(NAME c_consumer COMMAND c_consumer)
endif()
if(TARGET cpp17_consumer)
    add_test(NAME cpp17_consumer COMMAND cpp17_consumer)
    add_test(NAME cpp17_no_exceptions_consumer COMMAND cpp17_no_exceptions_consumer)
    add_test(NAME cpp17_throwing_consumer COMMAND cpp17_throwing_consumer)
endif()
