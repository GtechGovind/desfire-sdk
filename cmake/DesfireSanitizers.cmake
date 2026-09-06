include_guard(GLOBAL)

option(DESFIRE_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(DESFIRE_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(DESFIRE_ENABLE_TSAN "Enable ThreadSanitizer" OFF)

if(DESFIRE_ENABLE_TSAN AND (DESFIRE_ENABLE_ASAN OR DESFIRE_ENABLE_UBSAN))
    message(FATAL_ERROR "ThreadSanitizer must use its own build directory")
endif()

set(_desfire_sanitizers "")
if(DESFIRE_ENABLE_ASAN)
    list(APPEND _desfire_sanitizers address)
endif()
if(DESFIRE_ENABLE_UBSAN)
    list(APPEND _desfire_sanitizers undefined)
endif()
if(DESFIRE_ENABLE_TSAN)
    list(APPEND _desfire_sanitizers thread)
endif()

if(_desfire_sanitizers)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        message(FATAL_ERROR "Requested sanitizers require a Clang or GCC toolchain")
    endif()
    list(JOIN _desfire_sanitizers "," _desfire_sanitizer_list)
    add_library(desfire_sanitizers INTERFACE)
    target_compile_options(desfire_sanitizers INTERFACE
        "-fsanitize=${_desfire_sanitizer_list}" -fno-omit-frame-pointer)
    target_link_options(desfire_sanitizers INTERFACE "-fsanitize=${_desfire_sanitizer_list}")
endif()

# Attach requested instrumentation without changing dependencies or consumer flags.
function(desfire_apply_sanitizers target)
    if(TARGET desfire_sanitizers)
        target_link_libraries(${target} PRIVATE desfire_sanitizers)
    endif()
endfunction()
