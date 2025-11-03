#ifndef DH_H
#define DH_H

#include <uint256.h>
#include "ec.h"

int ec3dh_generate_keypair(const ec_domain_params_t *curve, uint256_t *private_key, ec_point_t *pubkey);
int ec3dh_compute_shared_secret_dk(ec_domain_params_t *curve, uint256_t *private_key, ec_point_t *peer_pubkey,
                                   uint8_t *encryption_key, size_t enc_key_len, uint8_t *mac_key, size_t mac_key_len);


#endif
