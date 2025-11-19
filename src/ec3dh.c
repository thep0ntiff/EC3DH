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

#include <modplus.h>
#include <uint256.h>
#include <stdio.h>
#include <string.h>

int ec3dh_generate_keypair(const ec_domain_params_t *curve, uint256_t *private_key, ec_point_t *pubkey) {
    
    if (kp_generate_private_key(curve, private_key) < 0) {
        fprintf(stderr, "Private key generation failed.\n");
        return -1;
    }
    
    ec_scalar_multiply(curve, private_key, &curve->G, pubkey);

    if (!ec_point_on_curve(curve, pubkey)) {
        fprintf(stderr, "Pubkey generation failed.\n");
        return -1;
    }


    return 0;
}

int ec3dh_compute_shared_secret_dk(ec_domain_params_t *curve, uint256_t *private_key, ec_point_t *peer_pubkey,
                                   uint8_t *encryption_key, size_t enc_key_len, uint8_t *mac_key, size_t mac_key_len) {
    
    ec_point_t shared_point = {0};

    if (!ec_point_on_curve(curve, peer_pubkey)) {
        fprintf(stderr, "Received pubkey is not on curve!\n");
        return -1;
    }

    if (peer_pubkey->infinity) {
        return -1;
    }

    
    ec_scalar_multiply(curve, private_key, peer_pubkey, &shared_point);
    
    if (shared_point.infinity) {
        return -1;
    }

    ec_jacobian_to_affine(curve, &shared_point, &shared_point);

    uint256_t shared_secret = shared_point.x;
    
    if (ecdh_derive_key(&shared_secret, "encryption", 
                        encryption_key, enc_key_len) < 0) {
        memset(&shared_secret, 0, sizeof(shared_secret));
        return -1;
    }

    if (ecdh_derive_key(&shared_secret, "authentication",
                        mac_key, mac_key_len) < 0) {
        memset(&shared_secret, 0, sizeof(shared_secret));
        memset(encryption_key, 0, enc_key_len);
        return -1;
    }

    memset(&shared_secret, 0, sizeof(shared_secret));

    return 0;
}
