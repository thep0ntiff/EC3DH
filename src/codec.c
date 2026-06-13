/*
 * codec.c
 *
 * SEC1 point and scalar serialization. See codec.h for the formats.
 */

#include "codec.h"
#include "secure_wipe.h"

#include <modplus.h>
#include <string.h>

static void u256_to_be_bytes(const uint256_t *v, uint8_t out[32]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++) {
            out[i * 8 + j] = (uint8_t)((v->limb[3 - i] >> (56 - j * 8)) & 0xFF);
        }
    }
}

static void u256_from_be_bytes(const uint8_t in[32], uint256_t *v) {
    for (int i = 0; i < 4; i++) {
        v->limb[3 - i] = 0;
        for (int j = 0; j < 8; j++) {
            v->limb[3 - i] = (v->limb[3 - i] << 8) | in[i * 8 + j];
        }
    }
}

/* Right-hand side of the curve equation: x^3 + a*x + b (mod p). */
static void curve_rhs(const ec_domain_params_t *curve, const uint256_t *x, uint256_t *rhs) {
    uint256_t x2, x3, ax;
    mod_mul(x, x, &curve->p, &x2);
    mod_mul(x, &x2, &curve->p, &x3);
    mod_mul(&curve->a, x, &curve->p, &ax);
    mod_add(&x3, &ax, &curve->p, rhs);
    mod_add(rhs, &curve->b, &curve->p, rhs);
}

int ec_point_to_bytes(const ec_domain_params_t *curve, const ec_point_t *P,
                      int compressed, uint8_t *out, size_t out_len) {
    ec_point_t A;
    size_t need = compressed ? EC_POINT_COMPRESSED_LEN : EC_POINT_UNCOMPRESSED_LEN;

    if (out_len < need) {
        return -1;
    }

    ec_jacobian_to_affine(curve, P, &A);
    if (A.infinity) {
        return -1;
    }

    if (compressed) {
        out[0] = (uint8_t)(0x02 | (A.y.limb[0] & 1));
        u256_to_be_bytes(&A.x, out + 1);
    } else {
        out[0] = 0x04;
        u256_to_be_bytes(&A.x, out + 1);
        u256_to_be_bytes(&A.y, out + 33);
    }

    return (int)need;
}

int ec_point_from_bytes(const ec_domain_params_t *curve,
                        const uint8_t *in, size_t in_len, ec_point_t *P) {
    uint256_t x, y;

    if (in == NULL || P == NULL) {
        return -1;
    }

    if (in_len == EC_POINT_UNCOMPRESSED_LEN && in[0] == 0x04) {
        u256_from_be_bytes(in + 1, &x);
        u256_from_be_bytes(in + 33, &y);

        if (uint256_cmp(&x, &curve->p) >= 0 || uint256_cmp(&y, &curve->p) >= 0) {
            return -1;
        }
    } else if (in_len == EC_POINT_COMPRESSED_LEN && (in[0] == 0x02 || in[0] == 0x03)) {
        uint256_t rhs, exp, y2;
        uint256_t one = {{1, 0, 0, 0}};

        /* sqrt via y = rhs^((p+1)/4) requires p == 3 (mod 4) */
        if ((curve->p.limb[0] & 3) != 3) {
            return -1;
        }

        u256_from_be_bytes(in + 1, &x);
        if (uint256_cmp(&x, &curve->p) >= 0) {
            return -1;
        }

        curve_rhs(curve, &x, &rhs);

        /* exp = (p + 1) / 4; p + 1 cannot overflow since p < 2^256 - 1 */
        uint256_add(&curve->p, &one, &exp);
        uint256_rshift1(&exp);
        uint256_rshift1(&exp);

        mod_exp(&rhs, &exp, &curve->p, &y);

        /* if rhs is a non-residue, the "square root" fails this check */
        mod_mul(&y, &y, &curve->p, &y2);
        if (uint256_cmp(&y2, &rhs) != 0) {
            return -1;
        }

        /* pick the root whose parity matches the prefix */
        if ((y.limb[0] & 1) != (uint64_t)(in[0] & 1)) {
            mod_sub(&curve->p, &y, &curve->p, &y);
        }
    } else {
        return -1;
    }

    P->x = x;
    P->y = y;
    memset(&P->z, 0, sizeof(P->z));
    P->z.limb[0] = 1;
    P->infinity = 0;

    if (!ec_point_on_curve(curve, P)) {
        memset(P, 0, sizeof(*P));
        P->infinity = 1;
        return -1;
    }

    return 0;
}

void ec_scalar_to_bytes(const uint256_t *k, uint8_t out[32]) {
    u256_to_be_bytes(k, out);
}

int ec_scalar_from_bytes(const ec_domain_params_t *curve,
                         const uint8_t in[32], uint256_t *k) {
    u256_from_be_bytes(in, k);

    if (uint256_is_zero(k) || uint256_cmp(k, &curve->n) >= 0) {
        secure_wipe(k, sizeof(*k));
        return -1;
    }

    return 0;
}
