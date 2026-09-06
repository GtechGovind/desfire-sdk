/**
 * @file modern_core_consumer.cpp
 * @brief Installed-package smoke test for canonical C++23 and C++26 EV3 headers and symbols.
 */
#include <desfire/ev3/ev3.hpp>

/**
 * @brief Build representative native and ISO commands through the installed modern core.
 * @return Zero when canonical builders and the ISO codec retain their documented wire fields.
 */
int main() {
    auto application = desfire::ev3::model::ApplicationId::make(0x123456);
    if (!application) {
        return 1;
    }

    auto native_command = desfire::ev3::native::checked::delete_application(application.value());
    if (!native_command || native_command.value().opcode() != 0xDA) {
        return 2;
    }

    auto iso_command = desfire::ev3::iso7816::checked::Command::get_challenge(16);
    if (!iso_command) {
        return 3;
    }

    auto encoded = desfire::ev3::iso7816::raw::encode(iso_command.value().apdu());
    if (!encoded || encoded.value().size() != 5 || encoded.value().at(1) != 0x84 ||
        encoded.value().at(4) != 0x10) {
        return 4;
    }

    return 0;
}
