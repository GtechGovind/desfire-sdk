# Depend on the public crypto library only. TLS is unnecessary, and OpenSSL
# headers stay private so consumers can choose another primitive provider.
find_package(OpenSSL 3.5 REQUIRED COMPONENTS Crypto)
desfire_add_library(crypto_openssl src/openssl.cpp)
add_library(desfire::crypto_openssl ALIAS crypto_openssl)
target_link_libraries(crypto_openssl PUBLIC foundation PRIVATE OpenSSL::Crypto)
target_include_directories(crypto_openssl PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
install(DIRECTORY include/ DESTINATION include)
