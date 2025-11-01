/*
 * ec3dh.c
 * Author: Vincent Paul
 *
 * This file contains functions regarding the Diffie-Hellman key-exchange and serves as the intended API
*/

#include "ec3dh.h"
#include "ec.h"
#include "pk.h"

#include <modplus.h>
#include <uint256.h>
#include <stdio.h>

int ec3dh_generate_keypair(const ec_domain_params_t *curve, uint256_t *private_key, ec_point_t *pubkey) {
    
    if (kp_generate_private_key(curve, private_key) < 0) {
        fprintf(stderr, "Private key generation failed.\n");
        return -1;
    }
    
    ec_scalar_multiply(curve, private_key, &curve->G, pubkey);

    if (ec_point_on_curve(curve, pubkey) != 0) {
        fprintf(stderr, "Pubkey generation failed.\n");
        return -1;
    }
    return 0;
}

int ec3dh_compute_shared_secret(ec_domain_params_t *curve, uint256_t *private_key, ec_point_t *peer_pubkey, uint256_t *shared_secret) {
    
    ec_point_t shared_point = {0};

    if (ec_point_on_curve(curve, peer_pubkey) != 0) {
        fprintf(stderr, "Received pubkey is not on curve!\n");
        return -1;
    }

    
    ec_scalar_multiply(curve, private_key, peer_pubkey, &shared_point);

    *shared_secret = shared_point.x;

    return 0;
}
