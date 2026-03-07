#ifndef ECDSA_H
#define ECDSA_H

#include <stdint.h>
#include <stddef.h>
#include "ec.h"

/*
 * ECDSA sign using RFC 6979 deterministic k.
 * The message is hashed internally with SHA-256.
 * sig_r, sig_s: 32-byte big-endian output signature components.
 * Returns 0 on success, -1 on failure.
 */
int ecdsa_sign(const ec_domain_params_t *curve,
               const uint256_t          *private_key,
               const uint8_t            *msg,
               size_t                    msg_len,
               uint8_t                   sig_r[32],
               uint8_t                   sig_s[32]);

/*
 * ECDSA verify.
 * The message is hashed internally with SHA-256.
 * public_key: signer's public key in Jacobian projective form (z=1 for affine).
 * sig_r, sig_s: 32-byte big-endian signature components.
 * Returns 1 if valid, 0 if invalid, -1 on error (bad key, etc.).
 */
int ecdsa_verify(const ec_domain_params_t *curve,
                 const ec_point_t         *public_key,
                 const uint8_t            *msg,
                 size_t                    msg_len,
                 const uint8_t             sig_r[32],
                 const uint8_t             sig_s[32]);

#endif
