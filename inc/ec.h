#ifndef EC_H
#define EC_H

#include <modplus.h>

typedef struct {
    uint256_t p;
    uint256_t a;
    uint256_t b;
    uint256_t G[2];
    uint256_t n;
    uint8_t h;
} ec_domain_params_t;

typedef struct {
    uint256_t x;
    uint256_t y;
    uint8_t infinity;
} ec_point_t;


void ec_negate_point(const ec_domain_params_t *curve, const ec_point_t *P, ec_point_t *R);
void ec_add_point(const ec_domain_params_t *curve, const ec_point_t *P, const ec_point_t *Q, ec_point_t *R);
void ec_scalar_multiply(const ec_domain_params_t *curve, const uint256_t *k, const ec_point_t *P, ec_point_t *R);

int ec_point_on_curve(const ec_domain_params_t *curve, const ec_point_t *P);

#endif
