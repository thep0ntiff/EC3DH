/*
 * ec3dh.c
 * Author: Vincent Paul
 *
 * This file contains functions regarding the Diffie-Hellman key-exchange and serves as the intended API
*/

#include "ec3dh.h"
#include "ec.h"
#include "pk.h"
#include "kdf.h"
#include "secure_wipe.h"

#include <modplus.h>
#include <uint256.h>
#include <string.h>

int ec3dh_generate_keypair(const ec_domain_params_t *curve, uint256_t *private_key, ec_point_t *pubkey) {

    if (kp_generate_private_key(curve, private_key) < 0) {
        return EC3DH_ERR_RNG;
    }

    /* ec_scalar_multiply returns the public key in affine form (z == 1) */
    ec_scalar_multiply(curve, private_key, &curve->G, pubkey);

    if (pubkey->infinity || !ec_point_on_curve(curve, pubkey)) {
        secure_wipe(private_key, sizeof(*private_key));
        return EC3DH_ERR_PUBKEY_INVALID;
    }

    return EC3DH_OK;
}

int ec3dh_compute_shared_secret_dk(const ec_domain_params_t *curve, const uint256_t *private_key, const ec_point_t *peer_pubkey,
                                   uint8_t *encryption_key, size_t enc_key_len, uint8_t *mac_key, size_t mac_key_len) {

    ec_point_t shared_point = {0};

    if (uint256_is_zero(private_key) || uint256_cmp(private_key, &curve->n) >= 0) {
        return EC3DH_ERR_PRIVKEY_RANGE;
    }

    if (peer_pubkey->infinity || !ec_point_on_curve(curve, peer_pubkey)) {
        return EC3DH_ERR_PUBKEY_INVALID;
    }

    ec_scalar_multiply(curve, private_key, peer_pubkey, &shared_point);

    if (shared_point.infinity) {
        secure_wipe(&shared_point, sizeof(shared_point));
        return EC3DH_ERR_SHARED_INFINITY;
    }

    ec_jacobian_to_affine(curve, &shared_point, &shared_point);

    uint256_t shared_secret = shared_point.x;
    secure_wipe(&shared_point, sizeof(shared_point));

    if (ecdh_derive_key(&shared_secret, "encryption",
                        encryption_key, enc_key_len) < 0) {
        secure_wipe(&shared_secret, sizeof(shared_secret));
        return EC3DH_ERR_KDF;
    }

    if (ecdh_derive_key(&shared_secret, "authentication",
                        mac_key, mac_key_len) < 0) {
        secure_wipe(&shared_secret, sizeof(shared_secret));
        secure_wipe(encryption_key, enc_key_len);
        return EC3DH_ERR_KDF;
    }

    secure_wipe(&shared_secret, sizeof(shared_secret));

    return EC3DH_OK;
}
