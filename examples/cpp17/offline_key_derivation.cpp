/** @file offline_key_derivation.cpp @brief Use the strict C++17 facade without exceptions. */
#include <desfire/cpp17.hpp>

#include <iostream>

/** @brief Run one stateless derivation and inspect its Result. */
int main() {
    using namespace desfire::cpp17;
    auto key = Aes128Key::import(Bytes(16));
    if (!key) {
        return 1;
    }
    auto result =
        offline::derive_nxp_aes128(key.value(), Bytes{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06});
    if (!result) {
        std::cerr << result.error().message << '\n';
        return 1;
    }
    std::cout << "derived AES-128 key: " << result.value().size() << " bytes\n";
    return 0;
}
