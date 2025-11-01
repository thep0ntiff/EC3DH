#ifndef DH_H
#define DH_H

#include <uint256.h>
#include "ec.h"

int ec3dh_generate_keypair(const ec_domain_params_t *curve, uint256_t *private_key, ec_point_t *pubkey);
int ec3dh_compute_shared_secret(ec_domain_params_t *curve, uint256_t *private_key, ec_point_t *peer_pubkey, uint256_t *shared_secret);


#endif
