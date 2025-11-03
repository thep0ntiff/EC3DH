#ifndef KDF_H
#define KDF_H

#include <stdint.h>
#include <stddef.h>
#include "ec.h"

/* HKDF-Extract: Extracts a pseudorandom key from input key material */
void hkdf_extract(const uint8_t *salt, size_t salt_len,
                  const uint8_t *ikm, size_t ikm_len,
                  uint8_t prk[32]);

/* HKDF-Expand: Expands a pseudorandom key to desired length */
int hkdf_expand(const uint8_t prk[32],
                const uint8_t *info, size_t info_len,
                uint8_t *okm, size_t okm_len);

/* Complete HKDF: Extract + Expand */
int hkdf(const uint8_t *salt, size_t salt_len,
         const uint8_t *ikm, size_t ikm_len,
         const uint8_t *info, size_t info_len,
         uint8_t *okm, size_t okm_len);

/* Convenience: Derive key from ECDH shared secret */
int ecdh_derive_key(const uint256_t *shared_secret,
                    const char *info,
                    uint8_t *output,
                    size_t output_len);

#endif
