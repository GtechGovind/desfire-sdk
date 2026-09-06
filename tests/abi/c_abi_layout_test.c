/** @file c_abi_layout_test.c @brief Compile-time ABI-v1 size, offset, and enum baseline. */
#include <desfire.h>

#include <stddef.h>
#include <stdint.h>

_Static_assert(sizeof(df_card) == 8, "df_card width changed");
_Static_assert(sizeof(df_raw_channel) == 8, "df_raw_channel width changed");
_Static_assert(sizeof(df_error) == 256, "df_error width changed");
_Static_assert(offsetof(df_error, code) == 0, "df_error code offset changed");
_Static_assert(offsetof(df_error, outcome) == 4, "df_error outcome offset changed");
_Static_assert(offsetof(df_error, device_status) == 8, "df_error status offset changed");
_Static_assert(offsetof(df_error, message) == 10, "df_error message offset changed");
_Static_assert(DF_OK == 0 && DF_INTERNAL == 17, "error enum endpoints changed");
_Static_assert(DF_NOT_SENT == 0 && DF_REJECTED == 1 && DF_SUCCEEDED == 2 && DF_UNKNOWN == 3,
               "outcome enum changed");
_Static_assert(DF_NATIVE == 0 && DF_ISO_WRAPPED == 1, "framing enum changed");
_Static_assert(DF_PLAIN == 0 && DF_MAC == 1 && DF_FULL == 3, "communication enum changed");

#if UINTPTR_MAX == UINT64_MAX
_Static_assert(sizeof(df_transport_v1) == 136, "64-bit transport descriptor changed");
_Static_assert(sizeof(df_key_request_v1) == 160, "64-bit key request changed");
_Static_assert(sizeof(df_key_provider_v1) == 104, "64-bit key provider changed");
_Static_assert(sizeof(df_authentication_info_v1) == 88, "authentication result changed");
_Static_assert(sizeof(df_picc_configuration_v1) == 104, "PICC configuration changed");
_Static_assert(sizeof(df_delegated_application_info_v1) == 88,
               "delegated application result changed");
_Static_assert(sizeof(df_transaction_operation_v1) == 112, "transaction operation changed");
_Static_assert(sizeof(df_native_request_v1) == 120, "native request changed");
_Static_assert(sizeof(df_native_secure_request_v1) == 152, "secure native request changed");
_Static_assert(sizeof(df_iso_apdu_v1) == 136, "ISO APDU descriptor changed");
_Static_assert(sizeof(df_delegated_application_configuration_v1) == 152,
               "delegated offline descriptor changed");
_Static_assert(offsetof(df_transport_v1, reserved) == 72, "transport reserved offset changed");
_Static_assert(offsetof(df_key_request_v1, reserved) == 96, "key request reserved offset changed");
_Static_assert(offsetof(df_key_provider_v1, reserved) == 40,
               "key provider reserved offset changed");
_Static_assert(offsetof(df_delegated_application_configuration_v1, reserved) == 88,
               "delegated descriptor reserved offset changed");
#endif

/** @brief Return success after all compile-time ABI checks pass. */
int main(void) {
    return 0;
}
