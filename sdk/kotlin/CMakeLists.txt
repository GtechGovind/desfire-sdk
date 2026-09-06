if(NOT ANDROID)
    find_package(JNI REQUIRED)
endif()
add_library(desfire_jni SHARED
    src/main/cpp/context.cpp
    src/main/cpp/entrypoints.cpp
    src/main/cpp/key_provider.cpp
    src/main/cpp/transport.cpp)
desfire_apply_cpp_policy(desfire_jni PRIVATE)
target_include_directories(desfire_jni PRIVATE ${JNI_INCLUDE_DIRS})
target_link_libraries(desfire_jni PRIVATE desfire_c)
set_target_properties(desfire_jni PROPERTIES CXX_VISIBILITY_PRESET hidden)
install(TARGETS desfire_jni LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

if(APPLE)
    set_target_properties(desfire_jni PROPERTIES INSTALL_RPATH "@loader_path")
elseif(UNIX)
    set_target_properties(desfire_jni PROPERTIES INSTALL_RPATH "$ORIGIN")
endif()
if(ANDROID)
    # Android packages shared objects by their .so names; versioned ELF SONAMEs cannot be loaded.
    set_target_properties(desfire_c PROPERTIES VERSION "" SOVERSION "")
    # Keep the statically linked crypto and C++ core out of the application's global symbol scope.
    target_link_options(desfire_c PRIVATE "LINKER:--exclude-libs,ALL")
    target_link_options(desfire_jni PRIVATE "LINKER:--exclude-libs,ALL")
endif()
