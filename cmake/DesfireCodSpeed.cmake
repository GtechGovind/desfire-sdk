include_guard(GLOBAL)

include(FetchContent)

# CodSpeed C++ v2.4.0 was built from commit f5a917fdd14db7293bd37acb682873fec19f8b6c.
# Its official release asset includes the instrument hooks, so one SHA-256 check covers the full
# benchmark dependency graph without a nested network fetch.
FetchContent_Declare(
    google_benchmark
    URL
        "https://github.com/CodSpeedHQ/codspeed-cpp/releases/download/v2.4.0/codspeed-cpp-v2.4.0.tar.gz"
    URL_HASH
        "SHA256=fe8f8a5f61ef0464df9fd3349491c358fdaa023d6cc17e3ca8d3cc6cd09c1634"
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    SOURCE_SUBDIR google_benchmark)

# The release asset vendors this exact directory. Declaring it first overrides the upstream
# fallback Git fetch and keeps configuration fully covered by the release-asset digest.
FetchContent_Declare(
    instrument_hooks_repo
    SOURCE_DIR "${FETCHCONTENT_BASE_DIR}/google_benchmark-src/core/instrument-hooks")

set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "Disable third-party benchmark tests" FORCE)
set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "Disable third-party GoogleTest tests" FORCE)
set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "Do not install the CI-only benchmark library" FORCE)
set(BENCHMARK_ENABLE_DOXYGEN OFF CACHE BOOL "Disable third-party benchmark documentation" FORCE)
set(BENCHMARK_INSTALL_DOCS OFF CACHE BOOL "Do not install third-party benchmark docs" FORCE)

FetchContent_MakeAvailable(google_benchmark)
