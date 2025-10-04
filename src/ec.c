/*
 * ec.c
 * Author: Vincent Paul
 *
 * This file contains point operations on elliptic curves
*/

#include "ec.h"
#include "curve_params.h"

#include <modplus.h>


static void ec_calculate_coordinates(const ec_domain_params_t *curve, const uint256_t *lambda, const ec_point_t *P, const ec_point_t *Q, ec_point_t *R) {

    uint256_t lambda2, delta_x, mx; // Most of these are for readability... For a "slim" function, remove these and use R as temporary value holder
    uint256_t two = {{2, 0, 0, 0}};


    // Calculate xR
    mod_exp(lambda, &two, &curve->p, &lambda2);
    mod_sub(&P->x, &Q->x, &curve->p, &delta_x);
    mod_sub(&lambda2, &delta_x, &curve->p, &R->x);

    // Calculate yR
    mod_sub(&P->x, &R->x, &curve->p, &delta_x);
    mod_mul(lambda, &delta_x, &curve->p, &mx);
    mod_sub(&mx, &P->y, &curve->p, &R->y);
   

}

void ec_negate_point(const ec_domain_params_t *curve, ec_point_t *P, ec_point_t *R) {

    

}


void ec_double_point(const ec_domain_params_t *curve, const ec_point_t *P, const ec_point_t *R) {

    uint256_t three = {{3, 0, 0, 0}};
    uint256_t two = {{2, 0, 0, 0}};
    uint256_t x2, y2, prod, sum, lambda;

    // Lambda
    mod_mul(&P->x, &P->x, &curve->p, &x2);
    mod_mul(&x2, &three, &curve->p, &prod);
    mod_add(&prod, &curve->a, &curve->p, &sum);
    mod_mul(&P->y, &two, &curve->p, &y2);
    mod_inv(&y2, &curve->p, &y2);
    mod_mul(&y2, &sum, &curve->p, &lambda);

    ec_calculate_coordinates(curve, &lambda, P, P, R);
}


void ec_add_point(const ec_domain_params_t *curve, ec_point_t *P, ec_point_t *Q, ec_point_t *R) {
    
    /* This function expects you to know what you're doing and does not check for bad input */
    
    if (!(uint256_cmp(&P->x, &Q->x) + (uint256_cmp(&Q->y, &P->y)))) {
        ec_double_point(curve, P, R);
        return;
    }
    
    if (P->infinity) {
        *R = *Q; 
        return;
    }
    if (Q->infinity) {
        *R = *P;
        return;
    }

    uint256_t lambda;
    uint256_t delta_y, delta_x;

    // Calculate Lambda
    mod_sub(&Q->y, &P->y, &curve->p, &delta_y);
    mod_sub(&Q->x, &P->x, &curve->p, &delta_x);
    mod_inv(&delta_x, &curve->p, &delta_x); // This is bad. Use Jacobian projective coords to avoid modular inversion
    mod_mul(&delta_y, &delta_x, &curve->p, &lambda);
    
    ec_calculate_coordinates(curve, &lambda, P, Q, R);
}


void ec_scalar_multiply(const ec_domain_params_t *curve) {

    
    
}

