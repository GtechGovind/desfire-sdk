# Platform PC/SC dependencies remain private to this separately packaged plugin.
desfire_add_library(transport_pcsc src/pcsc.cpp)
add_library(desfire::transport_pcsc ALIAS transport_pcsc)
target_link_libraries(transport_pcsc PUBLIC foundation)
target_include_directories(transport_pcsc PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)

if(APPLE)
    find_library(DESFIRE_PCSC_FRAMEWORK PCSC REQUIRED)
    target_link_libraries(transport_pcsc PRIVATE "-framework PCSC")
elseif(WIN32)
    target_link_libraries(transport_pcsc PRIVATE Winscard)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(PCSC REQUIRED IMPORTED_TARGET libpcsclite)
    target_link_libraries(transport_pcsc PRIVATE PkgConfig::PCSC)
endif()

install(DIRECTORY include/ DESTINATION include)
