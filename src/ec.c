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

#define W 5
#define L 256
#define TABLE_SIZE  (1 << (W - 2))


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

static inline uint64_t ct_mask_u64(uint64_t b) { return (uint64_t) (-(int64_t)b); }

static inline uint64_t ct_eq_u64(uint64_t a, uint64_t b) {
    uint64_t x = a ^ b;
    x |= x >> 32;
    x |= x >> 16;
    x |= x >> 8;
    x |= x >> 4;
    x |= x >> 2;
    x |= x >> 1;
    // now LSB is 0 iff x != 0, else 0
    return (uint64_t)((x & 1) ^ 1);
}


static inline uint64_t ct_mask(int b) {
    return -(uint64_t)b;
}


static inline uint64_t ct_abs(int64_t x) {
    uint64_t mask = -(x < 0);
    return (x + mask) ^ mask; // returns |x|
}

static void PointSetIdentity(ec_point_t *P) {
    memset(&P->x, 0, sizeof(uint256_t)); P->x.limb[0] = 1;
    memset(&P->y, 0, sizeof(uint256_t)); P->y.limb[0] = 1;
    memset(&P->z, 0, sizeof(uint256_t)); P->z.limb[0] = 0;
    P->infinity = 1;
}


static void CMovePoint(ec_point_t *dest, const ec_point_t *src, uint64_t sel) {
    uint64_t mask = ct_mask_u64(sel); // 0xFF.. if sel==1 else 0
    for (int i = 0; i < 4; ++i) {
        dest->x.limb[i] = (dest->x.limb[i] & ~mask) | (src->x.limb[i] & mask);
        dest->y.limb[i] = (dest->y.limb[i] & ~mask) | (src->y.limb[i] & mask);
        dest->z.limb[i] = (dest->z.limb[i] & ~mask) | (src->z.limb[i] & mask);
    }

    uint64_t inf_mask = (uint64_t)(-(int64_t)sel);
    dest->infinity = (uint8_t)((dest->infinity & ~inf_mask) | (src->infinity & inf_mask));
}

static void ConditionalNegatePoint(const ec_domain_params_t *curve, const ec_point_t *in, ec_point_t *out, uint64_t sign) {
    ec_point_t neg;
    ec_negate_point(curve, in, &neg);
    *out = *in;
    CMovePoint(out, &neg, sign);
}


static void PrecomputeTable(const ec_domain_params_t *curve, const ec_point_t *P, ec_point_t *T /*size TABLE_SIZE*/) {
    T[0] = *P;
    ec_point_t twoP;
    ec_double_point(curve, P, &twoP);

    for (int j = 1; j < TABLE_SIZE; ++j) {
        // T[j] = T[j-1] + twoP  (so sequence 1P,3P,5P,...)
        ec_add_point(curve, &T[j-1], &twoP, &T[j]);
    }
}

static void SelectFromTableConst(const ec_point_t *T, uint64_t j, uint64_t mask_nonzero, ec_point_t *S_out) {
    PointSetIdentity(S_out);
    for (uint64_t t = 0; t < TABLE_SIZE; ++t) {
        uint64_t eq = ct_eq_u64(j, t);
        uint64_t sel = eq & mask_nonzero;
        CMovePoint(S_out, &T[t], sel);
    }
}



// Constant-time wNAF encoder: writes L digits into d[].
// d[i].limb[0] = abs(di), d[i].limb[1] = sign bit (0 pos, 1 neg), others zero.
static void ec_wnaf_encode_const(const uint256_t *n, uint256_t *d) {
    uint256_t k = *n;
    memset(d, 0, L * sizeof(uint256_t));

    for (int i = 0; i < L; ++i) {
        uint64_t t = k.limb[0] & ((1ULL << W) - 1);

        uint64_t cond = (t > ((1ULL << (W-1)) - 1)) ? 1ULL : 0ULL;
        int64_t di_signed = (int64_t)t - (int64_t)(cond * (1ULL << W));

        int is_odd = (int)(k.limb[0] & 1);

        int64_t mask = -(int64_t)is_odd;
        di_signed &= mask;

        uint64_t sign_bit = (di_signed < 0) ? 1ULL : 0ULL;
        uint64_t abs_di = (uint64_t)(di_signed < 0 ? -di_signed : di_signed);

        d[i].limb[0] = abs_di;
        d[i].limb[1] = sign_bit;
        d[i].limb[2] = 0;
        d[i].limb[3] = 0;

        // Now compute k := (k - di) >> 1, handling negative di branchless
        // di256 = |di|
        uint256_t di256;
        memset(&di256, 0, sizeof(uint256_t));
        di256.limb[0] = abs_di;

        uint256_t tmp_add; uint256_add(&k, &di256, &tmp_add);
        uint256_t tmp_sub; uint256_sub(&k, &di256, &tmp_sub);

        // choose tmp = (di_signed < 0) ? tmp_add : tmp_sub
        uint64_t neg_mask = (di_signed < 0) ? ~0ULL : 0ULL; // all-ones if negative
        uint256_t tmp_chosen;
        for (int limb = 0; limb < 4; ++limb) {
            tmp_chosen.limb[limb] = (tmp_add.limb[limb] & neg_mask) | (tmp_sub.limb[limb] & ~neg_mask);
        }

        k = tmp_chosen;
        uint256_rshift1(&k);
    }
}

static void wnaf_mul_const(const ec_domain_params_t *curve, const ec_point_t *P_proj, const uint256_t *d, ec_point_t *Q_proj) {
    ec_point_t T[TABLE_SIZE];
    PrecomputeTable(curve, P_proj, T);
    PointSetIdentity(Q_proj);

    for (int idx = L - 1; idx >= 0; --idx) {

        ec_point_t Qd;
        ec_double_point(curve, Q_proj, &Qd);
        *Q_proj = Qd;

        uint64_t abs_val = d[idx].limb[0];
        uint64_t sign_bit = d[idx].limb[1] & 1ULL;
        uint64_t is_zero = ct_eq_u64(abs_val, 0);
        uint64_t mask_nonzero = 1 - is_zero;

        // j = (abs_val - 1) / 2  (safe if abs_val==0; selection masked by mask_nonzero)
        uint64_t j_raw = 0;
        if (abs_val != 0) j_raw = ((abs_val - 1) >> 1);

        ec_point_t S;
        SelectFromTableConst(T, j_raw, mask_nonzero, &S);

        ec_point_t A;
        ConditionalNegatePoint(curve, &S, &A, sign_bit & mask_nonzero);

        ec_point_t Qnew;
        ec_add_point(curve, Q_proj, &A, &Qnew);
        *Q_proj = Qnew;
    }
}




void ec_jacobian_to_affine(const ec_domain_params_t *curve, const ec_point_t *P, ec_point_t *R) {

    /* Converts a jacobian projective coordinate back to affine space
     * P is the jacobian projective coordinate and R is the affine coordinate 
     * For jacobian->affine, (x, y, z) -> (x*(z^-1)^2, y*(z^-1)^3) */

    uint256_t z_inv, z_squared, z_cubed = {{0}};

    mod_inv(&P->z, &curve->p, &z_inv);
    mod_mul(&z_inv, &z_inv, &curve->p, &z_squared);
    mod_mul(&P->x, &z_squared, &curve->p, &R->x);

    mod_mul(&z_squared, &z_inv, &curve->p, &z_cubed);
    mod_mul(&P->y, &z_cubed, &curve->p, &R->y);

    memset(&R->z, 0, sizeof(R->z));
    R->infinity = 0;

}

void ec_negate_point(const ec_domain_params_t *curve, const ec_point_t *P, ec_point_t *R) {

    if (P->infinity) {
        *R = *P;
        return;
    }
    
    R->x = P->x;
    mod_sub(&curve->p, &P->y, &curve->p, &R->y);
    R->z = P->z;
    R->infinity = P->infinity;
    

}


void ec_double_point(const ec_domain_params_t *curve, const ec_point_t *P, ec_point_t *R) {
    
    if (P->infinity || uint256_is_zero(&P->y)) {
        R->infinity = 1;
        memset(&R->x, 0, sizeof(R->x));
        memset(&R->y, 0, sizeof(R->y));
        return;
    }

    
    if (!uint256_is_zero(&P->z)) {
        
        uint256_t S, M = {{0}};
        uint256_t y_power_x, z_squared, m_squared = {{0}};
        uint256_t four = {{4, 0, 0, 0}};
        uint256_t two = {{2, 0, 0, 0}};
        uint256_t three = {{3, 0, 0, 0}};
        uint256_t eight = {{8, 0, 0, 0}};
        uint256_t temp = {{0}};

        mod_mul(&four, &P->x, &curve->p, &S);
        mod_mul(&P->y, &P->y, &curve->p, &y_power_x);
        mod_mul(&S, &y_power_x, &curve->p, &S);
        
        mod_mul(&P->z, &P->z, &curve->p, &z_squared);
        mod_sub(&P->x, &z_squared, &curve->p, &temp);
        mod_mul(&three, &temp, &curve->p, &temp);
        mod_add(&P->x, &z_squared, &curve->p, &M);
        mod_mul(&temp, &M, &curve->p, &M);

        mod_mul(&M, &M, &curve->p, &m_squared);
        mod_mul(&S, &two, &curve->p, &temp);
        mod_sub(&m_squared, &temp, &curve->p, &R->x);
        
        mod_sub(&S, &R->x, &curve->p, &temp);
        mod_mul(&M, &temp, &curve->p, &temp);
        mod_mul(&P->y, &P->y, &curve->p, &y_power_x);
        mod_mul(&P->y, &y_power_x, &curve->p, &y_power_x);
        mod_mul(&P->y, &y_power_x, &curve->p, &y_power_x);
        mod_mul(&eight, &y_power_x, &curve->p, &y_power_x);
        mod_sub(&temp, &y_power_x, &curve->p, &R->y);
        
        mod_mul(&two, &P->y, &curve->p, &temp);
        mod_mul(&temp, &P->z, &curve->p, &R->z);
        
        R->infinity = 0;

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

    if (!uint256_is_zero(&P->z) && !uint256_is_zero(&Q->z)) {
        
        uint256_t two = {{2, 0, 0, 0}};
        uint256_t U1, U2 = {{0}};
        uint256_t S1, S2 = {{0}};
        uint256_t H = {{0}};
        uint256_t r = {{0}};
        
        uint256_t z_power_x = {{0}};
        uint256_t h_squared = {{0}};
        uint256_t h_cubed = {{0}};
        uint256_t r_squared = {{0}};
        uint256_t temp, temp2 = {{0}};
        

        /* P->Z = Z1 and Q->Z = Z2
         * This Pattern also applies to the X and Y coordinate */

        mod_mul(&Q->z, &Q->z, &curve->p, &z_power_x);
        mod_mul(&P->x, &z_power_x, &curve->p, &U1);
        mod_mul(&P->z, &P->z, &curve->p, &z_power_x);
        mod_mul(&Q->x, &z_power_x, &curve->p, &U2);

        mod_mul(&Q->z, &Q->z, &curve->p, &z_power_x);
        mod_mul(&Q->z, &z_power_x, &curve->p, &z_power_x);
        mod_mul(&P->y, &z_power_x, &curve->p, &S1);
        mod_mul(&P->z, &P->z, &curve->p, &z_power_x);
        mod_mul(&P->z, &z_power_x, &curve->p, &z_power_x);
        mod_mul(&Q->y, &z_power_x, &curve->p, &S2);

        mod_sub(&U2, &U1, &curve->p, &H);
        mod_sub(&S2, &S1, &curve->p, &r);
        
        mod_mul(&H, &H, &curve->p, &h_squared);
        mod_mul(&h_squared, &U1, &curve->p, &temp);
        mod_mul(&temp, &two, &curve->p, &temp);
        mod_mul(&H, &H, &curve->p, &h_cubed);
        mod_mul(&H, &h_cubed, &curve->p, &h_cubed);
        mod_mul(&r, &r, &curve->p, &r_squared);
        mod_sub(&r_squared, &h_cubed, &curve->p, &r_squared);
        mod_sub(&r_squared, &temp, &curve->p, &R->x);

        mod_mul(&U1, &h_squared, &curve->p, &temp);
        mod_sub(&temp, &R->x, &curve->p, &temp);
        mod_mul(&r, &temp, &curve->p, &temp);
        mod_mul(&S1, &h_cubed, &curve->p, &temp2);
        mod_sub(&temp, &temp2, &curve->p, &R->y);

        mod_mul(&P->z, &Q->z, &curve->p, &temp);
        mod_mul(&temp, &H, &curve->p, &R->z);
        
        R->infinity = 0;

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
    uint256_t y2, x3, ax, rhs = {{0}};
    
    /* Calculate y2 = x3 + ax + b (mod p) for affine coordinates
     * Calculate y2 = x3 + axz4 + bz6 (mod p) for jacobian projective coords
     * Returns 0 if the point lies on the curve */
    
    if (!uint256_is_zero(&P->z)) {
        

        uint256_t z2, z4, z6, bz6 = {{0}};

        mod_mul(&P->y, &P->y, &curve->p, &y2);
        mod_mul(&P->x, &P->x, &curve->p, &x3);
        mod_mul(&P->x, &x3, &curve->p, &x3);
        mod_mul(&curve->a, &P->x, &curve->p, &ax);
        mod_mul(&P->z, &P->z, &curve->p, &z2);
        mod_mul(&z2, &z2, &curve->p, &z4);
        mod_mul(&z4, &z2, &curve->p, &z6);
        mod_mul(&ax, &z4, &curve->p, &ax);
        mod_mul(&curve->b, &z6, &curve->p, &bz6);
        mod_add(&x3, &ax, &curve->p, &rhs);
        mod_add(&rhs, &bz6, &curve->p, &rhs);

        return (uint256_cmp(&rhs, &y2) == 0);
    }


    mod_mul(&P->y, &P->y, &curve->p, &y2);
    mod_exp(&P->x, &(uint256_t){{3, 0, 0, 0}}, &curve->p, &x3);
    mod_mul(&curve->a, &P->x, &curve->p, &ax);
    mod_add(&x3, &ax, &curve->p, &rhs);
    mod_add(&rhs, &curve->b, &curve->p, &rhs);

    return uint256_cmp(&rhs, &y2);
}

void ec_scalar_multiply(const ec_domain_params_t *curve, const uint256_t *k, const ec_point_t *P, ec_point_t *R) {
    
    /* constant time wnaf */

    uint256_t d[L];
    ec_wnaf_encode_const(k, d);
    wnaf_mul_const(curve, P, d, R);

}
