/*
 * ec.c
 * Author: Vincent Paul
 *
 * This file contains point operations on elliptic curves
*/

#include "ec.h"
#include "curve_params.h"

#include <modplus.h>
#include <string.h>

#define W 5
/* Signed-digit (wNAF) recoding of a 256-bit scalar can carry into one
 * extra digit, so 257 digits are required to be lossless. */
#define L 257
#define TABLE_SIZE  (1 << (W - 2))


static void ec_calculate_coordinates(const ec_domain_params_t *curve, const uint256_t *lambda, const ec_point_t *P, const ec_point_t *Q, ec_point_t *R) {

    uint256_t lambda2, tmp, mx;


    // Calculate xR
    mod_mul(lambda, lambda, &curve->p, &lambda2);
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


/* The scalar-multiplication ladder works in homogeneous projective
 * coordinates (x = X/Z, y = Y/Z) so it can use the complete addition
 * formulas of Renes-Costello-Batina (EUROCRYPT 2016, Algorithm 1).
 * Those formulas are exception-free on prime-order curves: they handle
 * P == Q, P == -Q and the identity without any branching, which removes
 * the secret-dependent control flow the Jacobian add/double have.
 * The identity is (0 : 1 : 0). */

static void PointSetIdentity(ec_point_t *P) {
    memset(&P->x, 0, sizeof(uint256_t));
    memset(&P->y, 0, sizeof(uint256_t)); P->y.limb[0] = 1;
    memset(&P->z, 0, sizeof(uint256_t));
    P->infinity = 1;
}

/* Complete addition, homogeneous projective coordinates, any curve a.
 * b3 = 3*b mod p must be supplied by the caller. No branches. */
static void ec_complete_add(const ec_domain_params_t *curve, const uint256_t *b3,
                            const ec_point_t *P, const ec_point_t *Q, ec_point_t *R) {
    const uint256_t *prime = &curve->p;
    uint256_t t0, t1, t2, t3, t4, t5;
    uint256_t X3, Y3, Z3;

    mod_mul(&P->x, &Q->x, prime, &t0);
    mod_mul(&P->y, &Q->y, prime, &t1);
    mod_mul(&P->z, &Q->z, prime, &t2);
    mod_add(&P->x, &P->y, prime, &t3);
    mod_add(&Q->x, &Q->y, prime, &t4);
    mod_mul(&t3, &t4, prime, &t3);
    mod_add(&t0, &t1, prime, &t4);
    mod_sub(&t3, &t4, prime, &t3);
    mod_add(&P->x, &P->z, prime, &t4);
    mod_add(&Q->x, &Q->z, prime, &t5);
    mod_mul(&t4, &t5, prime, &t4);
    mod_add(&t0, &t2, prime, &t5);
    mod_sub(&t4, &t5, prime, &t4);
    mod_add(&P->y, &P->z, prime, &t5);
    mod_add(&Q->y, &Q->z, prime, &X3);
    mod_mul(&t5, &X3, prime, &t5);
    mod_add(&t1, &t2, prime, &X3);
    mod_sub(&t5, &X3, prime, &t5);
    mod_mul(&curve->a, &t4, prime, &Z3);
    mod_mul(b3, &t2, prime, &X3);
    mod_add(&X3, &Z3, prime, &Z3);
    mod_sub(&t1, &Z3, prime, &X3);
    mod_add(&t1, &Z3, prime, &Z3);
    mod_mul(&X3, &Z3, prime, &Y3);
    mod_add(&t0, &t0, prime, &t1);
    mod_add(&t1, &t0, prime, &t1);
    mod_mul(&curve->a, &t2, prime, &t2);
    mod_mul(b3, &t4, prime, &t4);
    mod_add(&t1, &t2, prime, &t1);
    mod_sub(&t0, &t2, prime, &t2);
    mod_mul(&curve->a, &t2, prime, &t2);
    mod_add(&t4, &t2, prime, &t4);
    mod_mul(&t1, &t4, prime, &t0);
    mod_add(&Y3, &t0, prime, &Y3);
    mod_mul(&t5, &t4, prime, &t0);
    mod_mul(&t3, &X3, prime, &X3);
    mod_sub(&X3, &t0, prime, &X3);
    mod_mul(&t3, &t1, prime, &t0);
    mod_mul(&t5, &Z3, prime, &Z3);
    mod_add(&Z3, &t0, prime, &Z3);

    R->x = X3;
    R->y = Y3;
    R->z = Z3;
    R->infinity = 0; /* identity is represented by Z == 0; flag fixed up by caller */
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

/* Branch-free negation in homogeneous coordinates: (X, p-Y, Z).
 * The identity (0 : 1 : 0) maps to (0 : p-1 : 0), which is the same
 * projective point, so no special case is needed. */
static void ConditionalNegatePoint(const ec_domain_params_t *curve, const ec_point_t *in, ec_point_t *out, uint64_t sign) {
    ec_point_t neg;
    neg.x = in->x;
    mod_sub(&curve->p, &in->y, &curve->p, &neg.y);
    neg.z = in->z;
    neg.infinity = in->infinity;
    *out = *in;
    CMovePoint(out, &neg, sign);
}


static void PrecomputeTable(const ec_domain_params_t *curve, const uint256_t *b3,
                            const ec_point_t *P, ec_point_t *T /*size TABLE_SIZE*/) {
    T[0] = *P;
    ec_point_t twoP;
    ec_complete_add(curve, b3, P, P, &twoP);

    for (int j = 1; j < TABLE_SIZE; ++j) {
        // T[j] = T[j-1] + twoP  (so sequence 1P,3P,5P,...)
        ec_complete_add(curve, b3, &T[j-1], &twoP, &T[j]);
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

/* P_h must be in homogeneous projective coordinates (identity = (0:1:0)).
 * Every group operation in the loop is a complete addition, so there is
 * no secret-dependent control flow at this level. Zero digits add the
 * identity instead of skipping the addition. */
static void wnaf_mul_const(const ec_domain_params_t *curve, const ec_point_t *P_h, const uint256_t *d, ec_point_t *Q_h) {
    ec_point_t T[TABLE_SIZE];
    uint256_t b3;

    mod_add(&curve->b, &curve->b, &curve->p, &b3);
    mod_add(&b3, &curve->b, &curve->p, &b3);

    PrecomputeTable(curve, &b3, P_h, T);
    PointSetIdentity(Q_h);

    for (int idx = L - 1; idx >= 0; --idx) {

        ec_complete_add(curve, &b3, Q_h, Q_h, Q_h);

        uint64_t abs_val = d[idx].limb[0];
        uint64_t sign_bit = d[idx].limb[1] & 1ULL;
        uint64_t is_zero = ct_eq_u64(abs_val, 0);
        uint64_t mask_nonzero = 1 - is_zero;

        // j = (abs_val - 1) / 2  (safe if abs_val==0; selection masked by mask_nonzero)
        // Use constant-time: when abs_val==0, mask_nonzero==0 so j_raw is masked out anyway
        uint64_t safe_abs = abs_val | (1 - mask_nonzero); // becomes 1 when abs_val==0, avoiding underflow
        uint64_t j_raw = ((safe_abs - 1) >> 1);

        ec_point_t S;
        SelectFromTableConst(T, j_raw, mask_nonzero, &S);

        ec_point_t A;
        ConditionalNegatePoint(curve, &S, &A, sign_bit & mask_nonzero);

        ec_complete_add(curve, &b3, Q_h, &A, Q_h);
    }
}




void ec_jacobian_to_affine(const ec_domain_params_t *curve, const ec_point_t *P, ec_point_t *R) {

    /* Converts a jacobian projective coordinate back to affine space
     * P is the jacobian projective coordinate and R is the affine coordinate
     * For jacobian->affine, (x, y, z) -> (x*(z^-1)^2, y*(z^-1)^3) */

    if (P->infinity || uint256_is_zero(&P->z)) {
        R->infinity = 1;
        memset(&R->x, 0, sizeof(R->x));
        memset(&R->y, 0, sizeof(R->y));
        memset(&R->z, 0, sizeof(R->z));
        return;
    }

    uint256_t z_inv, z_squared, z_cubed = {{0}};

    mod_inv(&P->z, &curve->p, &z_inv);
    mod_mul(&z_inv, &z_inv, &curve->p, &z_squared);
    mod_mul(&P->x, &z_squared, &curve->p, &R->x);

    mod_mul(&z_squared, &z_inv, &curve->p, &z_cubed);
    mod_mul(&P->y, &z_cubed, &curve->p, &R->y);

    memset(&R->z, 0, sizeof(R->z));
    R->z.limb[0] = 1;
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
        memset(&R->z, 0, sizeof(R->z));
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

    /* Note: equality of P and Q cannot be decided by comparing raw Jacobian
     * coordinates (equal X/Y with different Z are different affine points).
     * The doubling case is detected below via H == 0 && r == 0. */

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

        if (uint256_is_zero(&H)) {
            if (uint256_is_zero(&r)) {
                ec_double_point(curve, P, R);
            } else {
                R->infinity = 1;
                memset(&R->x, 0, sizeof(R->x));
                memset(&R->y, 0, sizeof(R->y));
                memset(&R->z, 0, sizeof(R->z));
            }
            return;
        }

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

    if (uint256_is_zero(&delta_x)) {
        if (uint256_is_zero(&delta_y)) {
            ec_double_point(curve, P, R);
        } else {
            R->infinity = 1;
            memset(&R->x, 0, sizeof(R->x));
            memset(&R->y, 0, sizeof(R->y));
            memset(&R->z, 0, sizeof(R->z));
        }
        return;
    }

    mod_inv(&delta_x, &curve->p, &delta_x);
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
    mod_mul(&P->x, &P->x, &curve->p, &x3);
    mod_mul(&P->x, &x3, &curve->p, &x3);
    mod_mul(&curve->a, &P->x, &curve->p, &ax);
    mod_add(&x3, &ax, &curve->p, &rhs);
    mod_add(&rhs, &curve->b, &curve->p, &rhs);

    return (uint256_cmp(&rhs, &y2) == 0);
}

void ec_scalar_multiply(const ec_domain_params_t *curve, const uint256_t *k, const ec_point_t *P, ec_point_t *R) {

    /* Fixed-length wNAF ladder built on complete addition formulas.
     * P may be affine or Jacobian (only its public shape is branched on);
     * the result is returned in affine form (z == 1). */

    uint256_t d[L];
    ec_point_t A, Q;

    ec_jacobian_to_affine(curve, P, &A);

    if (A.infinity) {
        /* k * O == O */
        memset(R, 0, sizeof(*R));
        R->infinity = 1;
        return;
    }

    /* affine (x, y) -> homogeneous (x : y : 1); A.z is already 1 */

    ec_wnaf_encode_const(k, d);
    wnaf_mul_const(curve, &A, d, &Q);

    /* homogeneous -> affine: (X : Y : Z) -> (X/Z, Y/Z); Z == 0 is the identity */
    if (uint256_is_zero(&Q.z)) {
        memset(R, 0, sizeof(*R));
        R->infinity = 1;
        return;
    }

    uint256_t z_inv;
    mod_inv(&Q.z, &curve->p, &z_inv);
    mod_mul(&Q.x, &z_inv, &curve->p, &R->x);
    mod_mul(&Q.y, &z_inv, &curve->p, &R->y);
    memset(&R->z, 0, sizeof(R->z));
    R->z.limb[0] = 1;
    R->infinity = 0;
}
