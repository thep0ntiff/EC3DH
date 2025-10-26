/*
 * ec.c
 * Author: Vincent Paul
 *
 * This file contains point operations on elliptic curves
*/

#include "ec.h"
#include "curve_params.h"

#include <modplus.h>
#include <stdio.h>
#include <string.h>

static void uint256_print_hex(const uint256_t *x) {
    for (int i = 0; i < 4; i++) {
        printf("%lx", x->limb[i]);
    }
}


static void ec_calculate_coordinates(const ec_domain_params_t *curve, const uint256_t *lambda, const ec_point_t *P, const ec_point_t *Q, ec_point_t *R) {

    uint256_t lambda2, tmp, mx; 
    uint256_t two = {{2, 0, 0, 0}};


    // Calculate xR
    mod_exp(lambda, &two, &curve->p, &lambda2);
    mod_sub(&lambda2, &P->x, &curve->p, &tmp);
    mod_sub(&tmp, &Q->x, &curve->p, &R->x);

    // Calculate yR
    mod_sub(&P->x, &R->x, &curve->p, &tmp);
    mod_mul(lambda, &tmp, &curve->p, &mx);
    mod_sub(&mx, &P->y, &curve->p, &R->y);
   

}

void ec_negate_point(const ec_domain_params_t *curve, const ec_point_t *P, ec_point_t *R) {

    if (P->infinity) {
        *R = *P;
        return;
    }
    
    R->x = P->x;
    mod_sub(&curve->p, &P->y, &curve->p, &R->y);
    R->infinity = P->infinity;
    

}


void ec_double_point(const ec_domain_params_t *curve, const ec_point_t *P, ec_point_t *R) {
    
    if (P->infinity) {
        R->infinity = 1;
        memset(&R->x, 0, sizeof(R->x));
        memset(&R->y, 0, sizeof(R->y));
        return;
    }

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
    R->infinity = 0;
}


void ec_add_point(const ec_domain_params_t *curve, const ec_point_t *P, const ec_point_t *Q, ec_point_t *R) {
    
    
    if (uint256_cmp(&P->x, &Q->x) == 0 && uint256_cmp(&P->y, &Q->y) == 0) { 
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
    R->infinity = 0;
}

int ec_point_on_curve(const ec_domain_params_t *curve, const ec_point_t *P) {
    if (P->infinity) return 1;
    uint256_t y2, x3, ax, rhs;
    
    /* Calculate y2 = x3 + ax + b (mod p)
     * Returns 0 if the point lies on the curve */
    
    mod_mul(&P->y, &P->y, &curve->p, &y2);
    mod_exp(&P->x, &(uint256_t){{3, 0, 0, 0}}, &curve->p, &x3);
    mod_mul(&curve->a, &P->x, &curve->p, &ax);
    mod_add(&x3, &ax, &curve->p, &rhs);
    mod_add(&rhs, &curve->b, &curve->p, &rhs);

    return uint256_cmp(&rhs, &y2);
}

void ec_scalar_multiply(const ec_domain_params_t *curve, const uint256_t *k, const ec_point_t *P, ec_point_t *R) {
    /* Double-and-add approach */

    ec_point_t Q, temp;
    Q.infinity = 1;  // Initialize accumulator to point-at-infinity

    printf("Starting scalar multiplication\n");

    for (int i = 255; i >= 0; i--) {
        /* Double Q */
        if (!Q.infinity) {
            ec_double_point(curve, &Q, &temp);  // temp = 2*Q
            Q = temp;
        }

        /* Print after doubling */
        printf("Bit %3d after doubling: Q = (", i);
        if (!Q.infinity) {
            uint256_print_hex(&Q.x);
            printf(",");
            uint256_print_hex(&Q.y);
        } else {
            printf("INFINITY");
        }
        printf("), infinity=%d\n", Q.infinity);

        /* Add P if current bit is 1 */
        if (uint256_test_bit(k, i)) {
            if (Q.infinity) {
                Q = *P;  // Q = P if Q was infinity
            } else {
                ec_add_point(curve, &Q, P, &temp);  // temp = Q + P
                Q = temp;
            }

            /* Print after addition */
            printf("Bit %3d after addition: Q = (", i);
            if (!Q.infinity) {
                uint256_print_hex(&Q.x);
                printf(",");
                uint256_print_hex(&Q.y);
            } else {
                printf("INFINITY");
            }
            printf("), infinity=%d\n", Q.infinity);
        }

    }

    *R = Q;

    printf("Scalar multiplication completed: R = (");
    if (!R->infinity) {
        uint256_print_hex(&R->x);
        printf(",");
        uint256_print_hex(&R->y);
    } else {
        printf("INFINITY");
    }
    printf("), infinity=%d\n", R->infinity);
}
