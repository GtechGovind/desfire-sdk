# Scripted transport has no platform dependencies and is also usable by examples.
desfire_add_library(transport_replay src/replay.cpp)
add_library(desfire::transport_replay ALIAS transport_replay)
target_link_libraries(transport_replay PUBLIC foundation)
target_include_directories(transport_replay PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
install(DIRECTORY include/ DESTINATION include)
