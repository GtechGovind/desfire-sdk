# Thread support is part of the transport contract; no reader or crypto library
# is needed to compile these shared types and interfaces.
find_package(Threads REQUIRED)
desfire_add_library(foundation src/bytes.cpp src/secure_buffer.cpp)
add_library(desfire::foundation ALIAS foundation)
target_include_directories(foundation PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_link_libraries(foundation PUBLIC Threads::Threads)
install(DIRECTORY include/ DESTINATION include)
