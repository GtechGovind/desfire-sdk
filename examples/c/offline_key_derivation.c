/** @file offline_key_derivation.c @brief Derive an AES key through the stable C99 ABI. */
#include <desfire.h>
#include <stdio.h>

/** @brief Run one stateless AN10922 derivation without a reader or card. */
int main(void) {
    const uint8_t master_key[16] = {0};
    const uint8_t diversification[] = {0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    df_buffer* derived = NULL;
    df_error error = {0};
    const int32_t status = df_offline_derive_nxp_aes128(
        master_key, sizeof(master_key), diversification, sizeof(diversification), &derived, &error);
    if (status != DF_OK) {
        fprintf(stderr, "derivation failed (%u): %s\n", error.code, error.message);
        return 1;
    }
    printf("derived AES-128 key: %zu bytes\n", df_buffer_size(derived));
    df_buffer_free(derived);
    return 0;
}
