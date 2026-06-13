#ifndef DH_H
#define DH_H

#include <stddef.h>
#include <uint256.h>
#include "ec.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Error codes returned by the ec3dh API. All errors are negative, so
 * `< 0` checks keep working. The library never prints; inspect the
 * return value to find out what went wrong. */
enum {
    EC3DH_OK                  = 0,
    EC3DH_ERR_RNG             = -1, /* system RNG failed */
    EC3DH_ERR_PRIVKEY_RANGE   = -2, /* private key not in [1, n-1] */
    EC3DH_ERR_PUBKEY_INVALID  = -3, /* peer/own public key not a valid curve point */
    EC3DH_ERR_SHARED_INFINITY = -4, /* shared point is the point at infinity */
    EC3DH_ERR_KDF             = -5, /* key derivation failed */
};

int ec3dh_generate_keypair(const ec_domain_params_t *curve, uint256_t *private_key, ec_point_t *pubkey);
int ec3dh_compute_shared_secret_dk(const ec_domain_params_t *curve, const uint256_t *private_key, const ec_point_t *peer_pubkey,
                                   uint8_t *encryption_key, size_t enc_key_len, uint8_t *mac_key, size_t mac_key_len);

#ifdef __cplusplus
}
#endif

#endif
