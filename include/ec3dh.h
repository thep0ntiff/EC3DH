#ifndef EC3DH_H
#define EC3DH_H

#include <modplus.h>

typedef struct {
    uint256_t p;
    uint256_t a;
    uint256_t b;
    uint256_t G[2];
    uint256_t n;
    uint8_t h;
} ecc_domain_params_t;

#endif