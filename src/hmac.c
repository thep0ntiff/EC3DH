/*
 * hmac.c 
 * Copyright (c) 2025 Vincent Paul. All Rights Reserved.
*/

#include "hmac.h"
#include "sha256.h"

#include <string.h>


void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t output[32]) {
    
    uint8_t k[64];
    uint8_t k_ipad[64];
    uint8_t k_opad[64];
    uint8_t inner_hash[32];
    SHA256_ctx_t ctx;
    
    if (key_len > 64) {
        sha256(key, key_len, k);
        memset(k + 32, 0, 32);
    } else {
        memcpy(k, key, key_len);
        memset(k + key_len, 0, 64 - key_len);
    }

    for (int i = 0; i < 64; i++) {
        k_ipad[i] = k[i] ^ 0x36;
        k_opad[i] = k[i] ^ 0x5c;
    }

    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, 64);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, inner_hash);

    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, 64);
    sha256_update(&ctx, inner_hash, 32);
    sha256_final(&ctx, output);

    memset(&ctx, 0, sizeof(ctx));
    memset(k, 0, 64);
    memset(k_ipad, 0, 64);
    memset(k_opad, 0, 64);
    memset(inner_hash, 0, 32);
}
