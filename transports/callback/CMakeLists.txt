# Consumer callbacks keep reader-specific SDKs outside the protocol dependency graph.
desfire_add_library(transport_callback src/callback.cpp)
add_library(desfire::transport_callback ALIAS transport_callback)
target_link_libraries(transport_callback PUBLIC foundation)
target_include_directories(transport_callback PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
install(DIRECTORY include/ DESTINATION include)
