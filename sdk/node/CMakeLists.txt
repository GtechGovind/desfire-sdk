cmake_minimum_required(VERSION 3.20)
project(desfire_node LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
find_path(NODE_INCLUDE_DIR node_api.h
    HINTS "$ENV{NODE_INCLUDE_DIR}" /opt/homebrew/include/node /usr/local/include/node /usr/include/node
    REQUIRED)
find_path(DESFIRE_C_INCLUDE_DIR desfire.h
    HINTS "${CMAKE_CURRENT_SOURCE_DIR}/../../c-api/include" "$ENV{DESFIRE_C_INCLUDE_DIR}"
    REQUIRED)
find_library(DESFIRE_C_LIBRARY NAMES desfire_c
    HINTS "$ENV{DESFIRE_C_LIBRARY_DIR}" "${DESFIRE_BUILD_DIR}/c-api"
    REQUIRED)

add_library(desfire_node MODULE native/addon.cpp)
target_include_directories(desfire_node PRIVATE "${NODE_INCLUDE_DIR}" "${DESFIRE_C_INCLUDE_DIR}")
target_link_libraries(desfire_node PRIVATE "${DESFIRE_C_LIBRARY}")
target_compile_definitions(desfire_node PRIVATE NAPI_VERSION=8)
target_compile_options(desfire_node PRIVATE
    $<$<CXX_COMPILER_ID:AppleClang,Clang,GNU>:-Wall -Wextra -Wpedantic -Wconversion -Wshadow>)
set_target_properties(desfire_node PROPERTIES PREFIX "" SUFFIX ".node")
if(APPLE)
    target_link_options(desfire_node PRIVATE "-undefined" "dynamic_lookup")
elseif(WIN32)
    find_library(NODE_LIBRARY NAMES node HINTS "$ENV{NODE_LIBRARY_DIR}" REQUIRED)
    target_link_libraries(desfire_node PRIVATE "${NODE_LIBRARY}")
endif()
