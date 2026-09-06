file(READ "${PROJECT_SOURCE_DIR}/api/ev3-api.sha256" DESFIRE_API_MANIFEST_SHA256)
string(STRIP "${DESFIRE_API_MANIFEST_SHA256}" DESFIRE_API_MANIFEST_SHA256)
set(DESFIRE_API_MANIFEST_SHA256 "${DESFIRE_API_MANIFEST_SHA256}" PARENT_SCOPE)
configure_file(src/detail/manifest.hpp.in
    "${CMAKE_CURRENT_BINARY_DIR}/generated/detail/manifest.hpp" @ONLY)

add_library(desfire_c SHARED
    src/adapters.cpp
    src/iso.cpp
    src/managed_advanced.cpp
    src/managed_extended.cpp
    src/native.cpp
    src/offline.cpp
    src/raw.cpp
    src/runtime.cpp)
add_library(desfire::c ALIAS desfire_c)
desfire_apply_cpp_policy(desfire_c PRIVATE)
set_target_properties(desfire_c PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    EXPORT_NAME c)
target_compile_definitions(desfire_c PRIVATE DESFIRE_C_EXPORTS)
target_link_libraries(desfire_c PRIVATE ev3_core crypto_openssl transport_callback)
target_include_directories(desfire_c
    PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated"
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
           $<INSTALL_INTERFACE:include>)
if(APPLE)
    target_link_options(desfire_c PRIVATE
        "LINKER:-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/exports/macos.exports")
    set_property(TARGET desfire_c APPEND PROPERTY LINK_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/exports/macos.exports")
elseif(MSVC)
    target_link_options(desfire_c PRIVATE
        "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/exports/windows.def")
elseif(UNIX)
    target_link_options(desfire_c PRIVATE
        "LINKER:--version-script=${CMAKE_CURRENT_SOURCE_DIR}/exports/linux.map")
    set_property(TARGET desfire_c APPEND PROPERTY LINK_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/exports/linux.map")
endif()

install(TARGETS desfire_c EXPORT desfireTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES include/desfire.h DESTINATION include)
install(DIRECTORY include/desfire DESTINATION include FILES_MATCHING PATTERN "*.h")
install(FILES abi/abi-v1.symbols DESTINATION ${CMAKE_INSTALL_DATADIR}/desfire-sdk/abi)
