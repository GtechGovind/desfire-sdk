include_guard(GLOBAL)

include(GNUInstallDirs)

# Apply the repository warning, language, visibility, and sanitizer policy to one C++ target.
function(desfire_apply_cpp_policy target visibility)
    if(NOT TARGET "${target}")
        message(FATAL_ERROR "desfire_apply_cpp_policy: unknown target '${target}'")
    endif()

    target_compile_features(${target} ${visibility} cxx_std_${DESFIRE_CXX_STANDARD})
    target_compile_options(${target} PRIVATE
        $<$<CXX_COMPILER_ID:AppleClang,Clang,GNU>:-Wall;-Wextra;-Wpedantic;-Wconversion;-Wshadow>
        $<$<CXX_COMPILER_ID:MSVC>:/W4;/permissive->)
    set_target_properties(${target} PROPERTIES
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN YES)
    if(TARGET desfire_sanitizers)
        # Instrument build-tree objects and final links without exporting a dependency on the
        # intentionally build-only sanitizer policy target.
        target_link_libraries(${target} PRIVATE $<BUILD_INTERFACE:desfire_sanitizers>)
    endif()
endfunction()

# Add an installed SDK library with consistent warnings and export rules.
#
# The selected implementation language is deliberately private. A C target or C++17 facade
# linking an installed library privately must not inherit the core's C++26 build mode. Modern
# C++ consumers select C++23 or C++26 explicitly when including the core headers.
function(desfire_add_library target)
    add_library(${target} ${ARGN})
    desfire_apply_cpp_policy(${target} PRIVATE)
    install(TARGETS ${target}
        EXPORT desfireTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endfunction()

# Add a private object partition used to keep large protocol domains independent.
function(desfire_add_object_library target)
    add_library(${target} OBJECT ${ARGN})
    desfire_apply_cpp_policy(${target} PRIVATE)
    # ev3_core objects are embedded in both the static modern core and the shared C ABI.
    set_target_properties(${target} PROPERTIES POSITION_INDEPENDENT_CODE ON)
endfunction()
