/*
 * ecdsa.c
 *
 * ECDSA sign / verify on any secp256r1 curve.
 * Deterministic k is generated per RFC 6979 §3.2 (HMAC-SHA-256).
 *
 * All arithmetic over the curve ORDER n uses GMP (mpz_t), which is
 * already linked via -lgmp.  This sidesteps any risk that libmodplus is
 * internally optimised for the secp256r1 FIELD prime p and would give
 * wrong results when called with n as the modulus.
 *
 * EC point operations (scalar multiplication, affine conversion, point
 * validation) continue to use the existing library because those
 * operations ARE over p and are already correct.
 *
 * Byte-order convention (matching kdf.c / curve_params.c):
 *   uint256_t limbs are little-endian (limb[0] = least-significant 64 bits).
 *   Serialised byte arrays are big-endian  (byte[0] = most-significant byte).
 */

#include "ecdsa.h"
#include "ec.h"
#include "sha256.h"
#include "hmac.h"
#include "pk.h"

#include <gmp.h>
#include <string.h>
#include <stddef.h>

/* ── serialisation helpers ── */

/* uint256_t → 32 big-endian bytes (limb[3] = most-significant limb). */
static void u256_to_be(const uint256_t *v, uint8_t out[32])
{
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 8; j++)
            out[i * 8 + j] = (uint8_t)(v->limb[3 - i] >> (56 - j * 8));
}

/* 32 big-endian bytes → uint256_t. */
static void be_to_u256(const uint8_t in[32], uint256_t *v)
{
    for (int i = 0; i < 4; i++) {
        v->limb[3 - i] = 0;
        for (int j = 0; j < 8; j++)
            v->limb[3 - i] |= (uint64_t)in[i * 8 + j] << (56 - j * 8);
    }
}

/* uint256_t → mpz_t (via big-endian bytes). */
static void u256_to_mpz(const uint256_t *v, mpz_t out)
{
    uint8_t bytes[32];
    u256_to_be(v, bytes);
    mpz_import(out, 32, 1, 1, 0, 0, bytes);
}

/* mpz_t → 32 big-endian bytes (zero-padded on the left). */
static void mpz_to_be32(const mpz_t v, uint8_t out[32])
{
    memset(out, 0, 32);
    size_t count = 0;
    unsigned char tmp[32];
    mpz_export(tmp, &count, 1, 1, 0, 0, v);
    if (count > 0 && count <= 32)
        memcpy(out + 32 - count, tmp, count);
}

/* uint256_t → mpz, reduce once mod n if >= n.
 * For a 256-bit hash and 256-bit n (close to 2^256) one subtraction suffices. */
static void hash_to_mpz_mod_n(const uint8_t hash[32], const mpz_t n, mpz_t e)
{
    mpz_import(e, 32, 1, 1, 0, 0, hash);
    mpz_mod(e, e, n);
}

/* ── RFC 6979 §3.2 deterministic-k generation ── */

/*
 * privkey_be  – 32-byte big-endian private key (int2octets)
 * hash        – 32-byte SHA-256 message digest
 * n           – curve order as mpz_t
 * k_be_out    – 32-byte big-endian output
 */
static void rfc6979_generate_k(const uint8_t  privkey_be[32],
                                const uint8_t  hash[32],
                                const mpz_t    n,
                                uint8_t        k_be_out[32])
{
    /* bits2octets(h1): reduce hash mod n, serialise as 32-byte big-endian. */
    mpz_t h_mpz;
    mpz_init(h_mpz);
    hash_to_mpz_mod_n(hash, n, h_mpz);
    uint8_t h1_octets[32];
    mpz_to_be32(h_mpz, h1_octets);
    mpz_clear(h_mpz);

    uint8_t V[32], K[32];
    memset(V, 0x01, 32);   /* Step b */
    memset(K, 0x00, 32);   /* Step c */

    /* Buffer: V(32) | marker(1) | privkey(32) | h1(32) = 97 bytes */
    uint8_t buf[97];

    /* Step d */
    memcpy(buf,      V,          32); buf[32] = 0x00;
    memcpy(buf + 33, privkey_be, 32);
    memcpy(buf + 65, h1_octets,  32);
    hmac_sha256(K, 32, buf, 97, K);

    /* Step e */
    hmac_sha256(K, 32, V, 32, V);

    /* Step f */
    memcpy(buf,      V,          32); buf[32] = 0x01;
    memcpy(buf + 33, privkey_be, 32);
    memcpy(buf + 65, h1_octets,  32);
    hmac_sha256(K, 32, buf, 97, K);

    /* Step g */
    hmac_sha256(K, 32, V, 32, V);

    /* Step h: generate T until k in [1, n-1]. */
    mpz_t k_cand;
    mpz_init(k_cand);
    for (;;) {
        hmac_sha256(K, 32, V, 32, V);
        memcpy(k_be_out, V, 32);

        mpz_import(k_cand, 32, 1, 1, 0, 0, k_be_out);
        if (mpz_sgn(k_cand) > 0 && mpz_cmp(k_cand, n) < 0)
            break;

        uint8_t v0[33];
        memcpy(v0, V, 32); v0[32] = 0x00;
        hmac_sha256(K, 32, v0, 33, K);
        hmac_sha256(K, 32, V,  32, V);
    }
    mpz_clear(k_cand);

    memset(buf,       0, sizeof(buf));
    memset(h1_octets, 0, 32);
    memset(V, 0, 32);
    memset(K, 0, 32);
}

/* ── ECDSA sign ── */

int ecdsa_sign(const ec_domain_params_t *curve,
               const uint256_t          *private_key,
               const uint8_t            *msg,
               size_t                    msg_len,
               uint8_t                   sig_r[32],
               uint8_t                   sig_s[32])
{
    if (!private_key || !msg || !sig_r || !sig_s) return -1;
    if (uint256_is_zero(private_key) || uint256_cmp(private_key, &curve->n) >= 0)
        return -1;

    /* Hash the message. */
    uint8_t hash[32];
    sha256(msg, msg_len, hash);

    /* Serialise private key for RFC 6979. */
    uint8_t privkey_be[32];
    u256_to_be(private_key, privkey_be);

    /* Load curve order and private key into GMP. */
    mpz_t n, privkey_mpz, e, k_mpz, r, s, tmp, kinv;
    mpz_inits(n, privkey_mpz, e, k_mpz, r, s, tmp, kinv, NULL);
    u256_to_mpz(&curve->n, n);
    mpz_import(privkey_mpz, 32, 1, 1, 0, 0, privkey_be);

    /* e = hash mod n */
    hash_to_mpz_mod_n(hash, n, e);

    uint8_t k_be[32];
    rfc6979_generate_k(privkey_be, hash, n, k_be);

    int ret = -1;
    for (int attempt = 0; attempt < 64; attempt++) {
        if (attempt > 0) {
            sha256(k_be, 32, hash);
            rfc6979_generate_k(privkey_be, hash, n, k_be);
        }

        mpz_import(k_mpz, 32, 1, 1, 0, 0, k_be);

        /* R = k·G (EC operation, over p — uses existing library). */
        uint256_t k_u256;
        be_to_u256(k_be, &k_u256);
        ec_point_t R_jac, R_aff;
        ec_scalar_multiply(curve, &k_u256, &curve->G, &R_jac);
        if (R_jac.infinity) continue;
        ec_jacobian_to_affine(curve, &R_jac, &R_aff);

        /* r = R.x mod n (GMP) */
        uint8_t rx_bytes[32];
        u256_to_be(&R_aff.x, rx_bytes);
        mpz_import(r, 32, 1, 1, 0, 0, rx_bytes);
        mpz_mod(r, r, n);
        if (mpz_sgn(r) == 0) continue;

        /* s = k⁻¹ · (e + r·privkey) mod n (GMP) */
        mpz_mul(tmp, r, privkey_mpz);
        mpz_mod(tmp, tmp, n);
        mpz_add(tmp, e, tmp);
        mpz_mod(tmp, tmp, n);
        if (!mpz_invert(kinv, k_mpz, n)) continue; /* k and n must be coprime */
        mpz_mul(s, kinv, tmp);
        mpz_mod(s, s, n);
        if (mpz_sgn(s) == 0) continue;

        mpz_to_be32(r, sig_r);
        mpz_to_be32(s, sig_s);
        ret = 0;
        break;
    }

    mpz_clears(n, privkey_mpz, e, k_mpz, r, s, tmp, kinv, NULL);
    memset(k_be,       0, 32);
    memset(privkey_be, 0, 32);
    return ret;
}

/* ── Variable-time 2-scalar simultaneous multiplication (Shamir's trick) ──
 *
 * Computes R = k1·P1 + k2·P2 in a single pass of 256 doublings instead of
 * two separate scalar multiplications.  This is ~2x faster for the doubling
 * portion (which dominates), at the cost of ~3/4 * 256 additions vs ~1/4 * 256
 * for the constant-time wNAF.  Net field-operation count is still materially
 * lower than two separate ct-wNAF calls.
 *
 * Variable-time is safe here because all inputs to ECDSA verify are PUBLIC:
 *   k1 = u1 = e·s⁻¹ mod n   (derived from public hash and signature)
 *   k2 = u2 = r·s⁻¹ mod n   (same)
 *   P1 = G  (public generator)
 *   P2 = Q  (public key)
 * No secret values flow through this function.
 */
static void ec_mul2add_vartime(const ec_domain_params_t *curve,
                               const uint256_t          *k1,
                               const ec_point_t         *P1,
                               const uint256_t          *k2,
                               const ec_point_t         *P2,
                               ec_point_t               *R)
{
    /* Precompute: T[0]=P1, T[1]=P2, T[2]=P1+P2 */
    ec_point_t T[3];
    T[0] = *P1;
    T[1] = *P2;
    ec_add_point(curve, P1, P2, &T[2]);

    /* Initialise R to the point at infinity. */
    memset(R, 0, sizeof(*R));
    R->x.limb[0] = 1;   /* matches PointSetIdentity in ec.c */
    R->y.limb[0] = 1;
    R->infinity   = 1;

    /* Process from the most-significant bit downward. */
    for (int i = 255; i >= 0; i--) {
        ec_point_t tmp;
        ec_double_point(curve, R, &tmp);
        *R = tmp;

        int b1 = (int)((k1->limb[i >> 6] >> (i & 63)) & 1);
        int b2 = (int)((k2->limb[i >> 6] >> (i & 63)) & 1);

        if (b1 | b2) {
            /*  b1 b2  → table index
             *   1  0  → 0  (P1)
             *   0  1  → 1  (P2)
             *   1  1  → 2  (P1+P2)          */
            int idx = b2 ? (b1 ? 2 : 1) : 0;
            ec_add_point(curve, R, &T[idx], &tmp);
            *R = tmp;
        }
    }
}

/* ── ECDSA verify ── */

int ecdsa_verify(const ec_domain_params_t *curve,
                 const ec_point_t         *public_key,
                 const uint8_t            *msg,
                 size_t                    msg_len,
                 const uint8_t             sig_r[32],
                 const uint8_t             sig_s[32])
{
    if (!public_key || !msg || !sig_r || !sig_s) return -1;

    if (public_key->infinity || !ec_point_on_curve(curve, public_key))
        return -1;

    /* Load n, r, s. */
    mpz_t n, r, s;
    mpz_inits(n, r, s, NULL);
    u256_to_mpz(&curve->n, n);
    mpz_import(r, 32, 1, 1, 0, 0, sig_r);
    mpz_import(s, 32, 1, 1, 0, 0, sig_s);

    /* r, s ∈ [1, n-1] */
    if (mpz_sgn(r) <= 0 || mpz_cmp(r, n) >= 0) { mpz_clears(n, r, s, NULL); return 0; }
    if (mpz_sgn(s) <= 0 || mpz_cmp(s, n) >= 0) { mpz_clears(n, r, s, NULL); return 0; }

    /* e = SHA-256(msg) mod n */
    uint8_t hash[32];
    sha256(msg, msg_len, hash);
    mpz_t e;
    mpz_init(e);
    hash_to_mpz_mod_n(hash, n, e);

    /* w = s⁻¹ mod n */
    mpz_t w;
    mpz_init(w);
    if (!mpz_invert(w, s, n)) {
        mpz_clears(n, r, s, e, w, NULL);
        return -1;
    }

    /* u1 = e·w mod n,  u2 = r·w mod n */
    mpz_t u1, u2;
    mpz_inits(u1, u2, NULL);
    mpz_mul(u1, e, w); mpz_mod(u1, u1, n);
    mpz_mul(u2, r, w); mpz_mod(u2, u2, n);

    /* Convert u1, u2 back to uint256_t for EC operations. */
    uint8_t u1_be[32], u2_be[32];
    mpz_to_be32(u1, u1_be);
    mpz_to_be32(u2, u2_be);
    uint256_t u1_u256, u2_u256;
    be_to_u256(u1_be, &u1_u256);
    be_to_u256(u2_be, &u2_u256);

    /* X = u1·G + u2·Q using Shamir's trick (single pass, variable-time).
     * All inputs are public so variable-time is safe. */
    ec_point_t X;
    ec_mul2add_vartime(curve, &u1_u256, &curve->G, &u2_u256, public_key, &X);

    int result = 0;
    if (!X.infinity) {
        ec_jacobian_to_affine(curve, &X, &X);

        /* Accept iff X.x mod n == r */
        uint8_t xcoord_be[32];
        u256_to_be(&X.x, xcoord_be);
        mpz_t x_mod_n;
        mpz_init(x_mod_n);
        mpz_import(x_mod_n, 32, 1, 1, 0, 0, xcoord_be);
        mpz_mod(x_mod_n, x_mod_n, n);
        result = (mpz_cmp(x_mod_n, r) == 0) ? 1 : 0;
        mpz_clear(x_mod_n);
    }

    mpz_clears(n, r, s, e, w, u1, u2, NULL);
    return result;
}
