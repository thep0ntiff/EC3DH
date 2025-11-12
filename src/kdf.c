/*
 * kdf.c
 *
*/

#include "kdf.h"
#include "hmac.h"
#include "sha256.h"

#include <string.h>
#include <stdio.h>

void hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, uint8_t prk[32]) {
    
    uint8_t default_salt[32] = {0};
    
    if (salt == NULL || salt_len == 0) {
        salt = default_salt;
        salt_len = 32;
    }
    
    // PRK = HMAC-Hash(salt, IKM)
    hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

int hkdf_expand(const uint8_t prk[32],
                const uint8_t *info, size_t info_len,
                uint8_t *okm, size_t okm_len) {
    
    // Max output length is 255 * hash_len (255 * 32 = 8160 bytes for SHA-256)
    if (okm_len > 255 * 32) {
        return -1;
    }
    
    uint8_t T[32] = {0};
    size_t T_len = 0;
    size_t offset = 0;
    uint8_t counter = 1;
    
    while (offset < okm_len) {
        uint8_t hmac_input[32 + 256 + 1];  // T || info || counter
        size_t hmac_input_len = 0;
        
        // Build: T(i-1) || info || counter
        if (T_len > 0) {
            memcpy(hmac_input, T, T_len);
            hmac_input_len += T_len;
        }
        
        if (info != NULL && info_len > 0) {
            memcpy(hmac_input + hmac_input_len, info, info_len);
            hmac_input_len += info_len;
        }
        
        hmac_input[hmac_input_len++] = counter;
        
        // T(i) = HMAC-Hash(PRK, T(i-1) || info || counter)
        hmac_sha256(prk, 32, hmac_input, hmac_input_len, T);
        T_len = 32;
        
        size_t to_copy = (okm_len - offset < 32) ? (okm_len - offset) : 32;
        memcpy(okm + offset, T, to_copy);
        offset += to_copy;
        
        counter++;
    }
    
    memset(T, 0, 32);
    
    return 0;
}

int hkdf(const uint8_t *salt, size_t salt_len,
         const uint8_t *ikm, size_t ikm_len,
         const uint8_t *info, size_t info_len,
         uint8_t *okm, size_t okm_len) {
    
    uint8_t prk[32];
    
    hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
    
    int result = hkdf_expand(prk, info, info_len, okm, okm_len);
    
    memset(prk, 0, 32);
    
    return result;
}

int ecdh_derive_key(const uint256_t *shared_secret,
                    const char *info,
                    uint8_t *output,
                    size_t output_len) {
    
    uint8_t secret_bytes[32];
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++) {
            secret_bytes[i * 8 + j] = (shared_secret->limb[3 - i] >> (56 - j * 8)) & 0xFF;
        }
    }
    
    int result = hkdf(NULL, 0,
                      secret_bytes, 32,
                      (const uint8_t *)info, strlen(info),
                      output, output_len);
    
    memset(secret_bytes, 0, 32);
    
    return result;
}
