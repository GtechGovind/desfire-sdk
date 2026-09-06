# Fixed independent wire and crypto expectations; no physical reader required.
function(desfire_c_header_compile_test header)
    file(RELATIVE_PATH relative_header "${PROJECT_SOURCE_DIR}/c-api/include" "${header}")
    string(MAKE_C_IDENTIFIER "${relative_header}" target_suffix)
    set(source "${CMAKE_CURRENT_BINARY_DIR}/header-self-contained/c_${target_suffix}.c")
    file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/header-self-contained")
    file(WRITE "${source}" "#include <${relative_header}>\n")
    add_library(c_header_${target_suffix} OBJECT "${source}")
    set_target_properties(c_header_${target_suffix} PROPERTIES
        C_STANDARD 99
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO)
    target_include_directories(c_header_${target_suffix} PRIVATE
        "${PROJECT_SOURCE_DIR}/c-api/include")
endfunction()

function(desfire_cpp17_header_compile_test header)
    file(RELATIVE_PATH relative_header "${PROJECT_SOURCE_DIR}/sdk/cpp17/include" "${header}")
    string(MAKE_C_IDENTIFIER "${relative_header}" target_suffix)
    set(source "${CMAKE_CURRENT_BINARY_DIR}/header-self-contained/cpp17_${target_suffix}.cpp")
    file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/header-self-contained")
    file(WRITE "${source}" "#include <${relative_header}>\n")
    add_library(cpp17_header_${target_suffix} OBJECT "${source}")
    set_target_properties(cpp17_header_${target_suffix} PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS NO)
    target_include_directories(cpp17_header_${target_suffix} PRIVATE
        "${PROJECT_SOURCE_DIR}/sdk/cpp17/include"
        "${PROJECT_SOURCE_DIR}/sdk/generated"
        "${PROJECT_SOURCE_DIR}/c-api/include")
endfunction()

function(desfire_modern_header_compile_test header include_root)
    file(RELATIVE_PATH relative_header "${include_root}" "${header}")
    string(MAKE_C_IDENTIFIER "${relative_header}" target_suffix)
    set(source "${CMAKE_CURRENT_BINARY_DIR}/header-self-contained/modern_${target_suffix}.cpp")
    file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/header-self-contained")
    file(WRITE "${source}" "#include <${relative_header}>\n")
    add_library(modern_header_${target_suffix} OBJECT "${source}")
    desfire_apply_cpp_policy(modern_header_${target_suffix} PRIVATE)
    target_include_directories(modern_header_${target_suffix} PRIVATE
        "${PROJECT_SOURCE_DIR}/foundation/include"
        "${PROJECT_SOURCE_DIR}/core/include")
endfunction()

file(GLOB_RECURSE desfire_foundation_public_headers CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/foundation/include/*.hpp")
foreach(header IN LISTS desfire_foundation_public_headers)
    desfire_modern_header_compile_test("${header}" "${PROJECT_SOURCE_DIR}/foundation/include")
endforeach()

file(GLOB_RECURSE desfire_core_public_headers CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/core/include/*.hpp")
foreach(header IN LISTS desfire_core_public_headers)
    desfire_modern_header_compile_test("${header}" "${PROJECT_SOURCE_DIR}/core/include")
endforeach()

function(desfire_test name source)
    add_executable(${name} ${source})
    desfire_apply_cpp_policy(${name} PRIVATE)
    target_link_libraries(${name} PRIVATE ev3_core transport_replay)
    add_test(NAME ${name} COMMAND ${name})
endfunction()

desfire_test(ev3_native_raw_test unit/ev3_native_raw_test.cpp)
desfire_test(ev3_native_checked_test unit/ev3_native_checked_test.cpp)
if(TARGET crypto_openssl)
    desfire_test(ev3_iso7816_test unit/ev3_iso7816_test.cpp)
    target_link_libraries(ev3_iso7816_test PRIVATE crypto_openssl)
endif()
if(TARGET crypto_openssl)
    desfire_test(ev3_security_test unit/ev3_security_test.cpp)
    target_link_libraries(ev3_security_test PRIVATE crypto_openssl)
    desfire_test(ev3_standard_aes_test unit/ev3_standard_aes_test.cpp)
    target_link_libraries(ev3_standard_aes_test PRIVATE crypto_openssl)
endif()
if(TARGET desfire_c)
    file(GLOB_RECURSE desfire_c_public_headers CONFIGURE_DEPENDS
        "${PROJECT_SOURCE_DIR}/c-api/include/*.h")
    foreach(header IN LISTS desfire_c_public_headers)
        desfire_c_header_compile_test("${header}")
    endforeach()

    file(GLOB_RECURSE desfire_cpp17_public_headers CONFIGURE_DEPENDS
        "${PROJECT_SOURCE_DIR}/sdk/cpp17/include/*.hpp")
    foreach(header IN LISTS desfire_cpp17_public_headers)
        desfire_cpp17_header_compile_test("${header}")
    endforeach()

    add_executable(c_abi_layout_test abi/c_abi_layout_test.c)
    set_target_properties(c_abi_layout_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO)
    desfire_apply_sanitizers(c_abi_layout_test)
    target_link_libraries(c_abi_layout_test PRIVATE desfire_c)
    add_test(NAME c_abi_layout_test COMMAND c_abi_layout_test)

    add_executable(c_abi_test unit/c_abi_test.c)
    set_target_properties(c_abi_test PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED YES)
    desfire_apply_sanitizers(c_abi_test)
    target_compile_definitions(c_abi_test PRIVATE
        DESFIRE_EXPECTED_MANIFEST_SHA256="${DESFIRE_API_MANIFEST_SHA256}")
    target_link_libraries(c_abi_test PRIVATE desfire_c)
    add_test(NAME c_abi_test COMMAND c_abi_test)
    add_executable(cpp17_test unit/cpp17_test.cpp)
    set_target_properties(cpp17_test PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    desfire_apply_sanitizers(cpp17_test)
    target_link_libraries(cpp17_test PRIVATE desfire::cpp17)
    add_test(NAME cpp17_test COMMAND cpp17_test)

    add_executable(cpp17_no_exceptions_test unit/cpp17_test.cpp)
    set_target_properties(cpp17_no_exceptions_test PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS NO)
    desfire_apply_sanitizers(cpp17_no_exceptions_test)
    target_link_libraries(cpp17_no_exceptions_test PRIVATE desfire::cpp17)
    if(MSVC)
        target_compile_options(cpp17_no_exceptions_test PRIVATE /EHs-c-)
    else()
        target_compile_options(cpp17_no_exceptions_test PRIVATE -fno-exceptions)
    endif()
    add_test(NAME cpp17_no_exceptions_test COMMAND cpp17_no_exceptions_test)

    add_executable(cpp17_throwing_test unit/cpp17_throwing_test.cpp)
    set_target_properties(cpp17_throwing_test PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS NO)
    desfire_apply_sanitizers(cpp17_throwing_test)
    target_link_libraries(cpp17_throwing_test PRIVATE desfire::cpp17)
    add_test(NAME cpp17_throwing_test COMMAND cpp17_throwing_test)
endif()
if(TARGET crypto_openssl)
    desfire_test(ev3_long_exchange_test scenarios/ev3_long_exchange_test.cpp)
    target_link_libraries(ev3_long_exchange_test PRIVATE crypto_openssl transport_callback)
endif()

if(TARGET crypto_openssl)
    add_executable(ev3_codec_session_benchmark benchmarks/ev3_codec_session_benchmark.cpp)
    desfire_apply_cpp_policy(ev3_codec_session_benchmark PRIVATE)
    target_link_libraries(ev3_codec_session_benchmark PRIVATE ev3_core crypto_openssl)
    add_test(NAME ev3_codec_session_benchmark
        COMMAND ev3_codec_session_benchmark --iterations 2000)
    set_tests_properties(ev3_codec_session_benchmark PROPERTIES LABELS benchmark TIMEOUT 30)
endif()
if(TARGET crypto_openssl)
    desfire_test(ev3_card_test unit/ev3_card_test.cpp)
    target_link_libraries(ev3_card_test PRIVATE crypto_openssl transport_callback)
endif()

if(TARGET crypto_openssl)
    desfire_test(ev3_offline_test unit/ev3_offline_test.cpp)
    target_link_libraries(ev3_offline_test PRIVATE crypto_openssl)
endif()
if(DESFIRE_BUILD_FUZZERS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "The fuzz target requires Clang/libFuzzer")
    endif()
    target_compile_options(ev3_core PRIVATE -fsanitize=fuzzer-no-link)
    add_executable(ev3_parser_fuzz fuzz/ev3_parser_fuzz.cpp)
    desfire_apply_cpp_policy(ev3_parser_fuzz PRIVATE)
    target_link_libraries(ev3_parser_fuzz PRIVATE ev3_core)
    target_compile_options(ev3_parser_fuzz PRIVATE -fsanitize=fuzzer)
    target_link_options(ev3_parser_fuzz PRIVATE -fsanitize=fuzzer)
endif()
add_executable(ev3_parser_stress fuzz/ev3_parser_fuzz.cpp fuzz/ev3_parser_stress.cpp)
desfire_apply_cpp_policy(ev3_parser_stress PRIVATE)
target_link_libraries(ev3_parser_stress PRIVATE ev3_core)
add_test(NAME ev3_parser_stress COMMAND ev3_parser_stress)
