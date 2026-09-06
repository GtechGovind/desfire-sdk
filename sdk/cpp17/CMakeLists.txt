# The C++17 facade contains ownership and type conversion only. Protocol and crypto
# behavior stay behind the versioned C ABI, so modern-core requirements do not leak.
add_library(desfire_cpp17 INTERFACE)
add_library(desfire::cpp17 ALIAS desfire_cpp17)
set_target_properties(desfire_cpp17 PROPERTIES EXPORT_NAME cpp17)
target_compile_features(desfire_cpp17 INTERFACE cxx_std_17)
target_compile_options(desfire_cpp17 INTERFACE
    $<$<CXX_COMPILER_ID:MSVC>:/Zc:__cplusplus>)
target_link_libraries(desfire_cpp17 INTERFACE desfire_c)
target_include_directories(desfire_cpp17 INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/sdk/generated>
    $<INSTALL_INTERFACE:include>)
install(TARGETS desfire_cpp17 EXPORT desfireTargets)
install(DIRECTORY include/ DESTINATION include)
install(FILES ${PROJECT_SOURCE_DIR}/sdk/generated/operation_manifest.generated.hpp
        DESTINATION include)
