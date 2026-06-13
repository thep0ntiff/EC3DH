/*
 * kat.c
 *
 * Known-answer tests (KATs) for the EC3DH library.
 *
 * Vector sources:
 *  - SHA-256:      NIST FIPS 180-4 examples / NIST CAVP
 *  - HMAC-SHA256:  RFC 4231 test cases 1, 2, 3, 6
 *  - HKDF-SHA256:  RFC 5869 test cases 1 and 3
 *  - P-256 k*G:    well-known multiples of the base point
 *  - ECDH P-256:   NIST CAVP ECC CDH component test, vector 0
 *
 * All vectors were independently cross-checked against a separate
 * big-integer implementation before being embedded here.
 */

#include "ec.h"
#include "curve_params.h"
#include "ec3dh.h"
#include "pk.h"
#include "kdf.h"
#include "hmac.h"
#include "sha256.h"
#include "codec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_failed = 0;

static void check(int ok, const char *name) {
    tests_run++;
    if (!ok) {
        tests_failed++;
        printf("FAIL  %s\n", name);
    } else {
        printf("ok    %s\n", name);
    }
}

/* ---------- helpers ---------- */

static uint8_t hex_nibble(char c) {
    if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
    if (c >= 'a' && c <= 'f') return (uint8_t)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (uint8_t)(c - 'A' + 10);
    fprintf(stderr, "bad hex char '%c'\n", c);
    exit(1);
}

static void hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    if (strlen(hex) != out_len * 2) {
        fprintf(stderr, "bad hex length for %s\n", hex);
        exit(1);
    }
    for (size_t i = 0; i < out_len; i++) {
        out[i] = (uint8_t)((hex_nibble(hex[2 * i]) << 4) | hex_nibble(hex[2 * i + 1]));
    }
}

/* Parse a 64-char big-endian hex string into a uint256_t (limb[0] = LSW). */
static uint256_t u256(const char *hex) {
    uint8_t bytes[32];
    uint256_t r;
    hex_to_bytes(hex, bytes, 32);
    for (int i = 0; i < 4; i++) {
        r.limb[3 - i] = 0;
        for (int j = 0; j < 8; j++) {
            r.limb[3 - i] = (r.limb[3 - i] << 8) | bytes[i * 8 + j];
        }
    }
    return r;
}

/* Build an affine point from big-endian hex coordinates. */
static ec_point_t point(const char *x_hex, const char *y_hex) {
    ec_point_t P;
    P.x = u256(x_hex);
    P.y = u256(y_hex);
    memset(&P.z, 0, sizeof(P.z));
    P.z.limb[0] = 1;
    P.infinity = 0;
    return P;
}

static int u256_eq(const uint256_t *a, const uint256_t *b) {
    return uint256_cmp(a, b) == 0;
}

/* Compare a (possibly Jacobian) point against expected affine coordinates. */
static int point_eq_affine(const ec_point_t *P, const char *x_hex, const char *y_hex) {
    ec_point_t A;
    uint256_t ex = u256(x_hex), ey = u256(y_hex);
    ec_jacobian_to_affine(&secp256r1, P, &A);
    return !A.infinity && u256_eq(&A.x, &ex) && u256_eq(&A.y, &ey);
}

/* ---------- SHA-256 ---------- */

static void test_sha256_one(const uint8_t *msg, size_t len, const char *digest_hex, const char *name) {
    uint8_t expected[32], got[32];
    hex_to_bytes(digest_hex, expected, 32);
    sha256(msg, len, got);
    check(memcmp(got, expected, 32) == 0, name);
}

static void test_sha256(void) {
    uint8_t buf[64];

    test_sha256_one((const uint8_t *)"abc", 3,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "sha256: 'abc'");

    test_sha256_one((const uint8_t *)"", 0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "sha256: empty message");

    /* 56 bytes: hits the padding branch that needs an extra block */
    test_sha256_one((const uint8_t *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        "sha256: 56-byte two-block message");

    memset(buf, 'a', 63);
    test_sha256_one(buf, 63,
        "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34",
        "sha256: 63-byte message");

    memset(buf, 'a', 64);
    test_sha256_one(buf, 64,
        "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
        "sha256: 64-byte (exact block) message");
}

/* ---------- HMAC-SHA256 (RFC 4231) ---------- */

static void test_hmac_one(const uint8_t *key, size_t key_len,
                          const uint8_t *data, size_t data_len,
                          const char *mac_hex, const char *name) {
    uint8_t expected[32], got[32];
    hex_to_bytes(mac_hex, expected, 32);
    hmac_sha256(key, key_len, data, data_len, got);
    check(memcmp(got, expected, 32) == 0, name);
}

static void test_hmac(void) {
    uint8_t key[131];

    memset(key, 0x0b, 20);
    test_hmac_one(key, 20, (const uint8_t *)"Hi There", 8,
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        "hmac: RFC 4231 test case 1");

    test_hmac_one((const uint8_t *)"Jefe", 4,
        (const uint8_t *)"what do ya want for nothing?", 28,
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        "hmac: RFC 4231 test case 2");

    {
        uint8_t data[50];
        memset(key, 0xaa, 20);
        memset(data, 0xdd, 50);
        test_hmac_one(key, 20, data, 50,
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            "hmac: RFC 4231 test case 3");
    }

    /* key longer than the block size: exercises the key-hashing path */
    memset(key, 0xaa, 131);
    test_hmac_one(key, 131,
        (const uint8_t *)"Test Using Larger Than Block-Size Key - Hash Key First", 54,
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        "hmac: RFC 4231 test case 6 (long key)");
}

/* ---------- HKDF-SHA256 (RFC 5869) ---------- */

static void test_hkdf(void) {
    uint8_t ikm[22], salt[13], info[10], okm[42], expected[42];

    memset(ikm, 0x0b, 22);
    hex_to_bytes("000102030405060708090a0b0c", salt, 13);
    hex_to_bytes("f0f1f2f3f4f5f6f7f8f9", info, 10);
    hex_to_bytes("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                 "34007208d5b887185865", expected, 42);
    check(hkdf(salt, 13, ikm, 22, info, 10, okm, 42) == 0 &&
          memcmp(okm, expected, 42) == 0,
          "hkdf: RFC 5869 test case 1");

    /* no salt, no info: exercises the default-salt path in hkdf_extract */
    hex_to_bytes("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
                 "9d201395faa4b61a96c8", expected, 42);
    check(hkdf(NULL, 0, ikm, 22, NULL, 0, okm, 42) == 0 &&
          memcmp(okm, expected, 42) == 0,
          "hkdf: RFC 5869 test case 3 (no salt/info)");

    check(hkdf(NULL, 0, ikm, 22, NULL, 0, okm, 0) == 0,
          "hkdf: zero-length output accepted");
}

/* ---------- P-256 scalar multiplication ---------- */

static void test_scalar_mult_one(const char *k_hex, const char *x_hex, const char *y_hex,
                                 const char *name) {
    uint256_t k = u256(k_hex);
    ec_point_t R;
    ec_scalar_multiply(&secp256r1, &k, &secp256r1.G, &R);
    check(point_eq_affine(&R, x_hex, y_hex), name);
}

static void test_scalar_mult(void) {
    test_scalar_mult_one(
        "0000000000000000000000000000000000000000000000000000000000000001",
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        "ecmul: 1*G == G");

    test_scalar_mult_one(
        "0000000000000000000000000000000000000000000000000000000000000002",
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1",
        "ecmul: 2*G");

    test_scalar_mult_one(
        "0000000000000000000000000000000000000000000000000000000000000003",
        "5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c",
        "8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032",
        "ecmul: 3*G");

    test_scalar_mult_one(
        "0000000000000000000000000000000000000000000000000000000000000005",
        "51590b7a515140d2d784c85608668fdfef8c82fd1f5be52421554a0dc3d033ed",
        "e0c17da8904a727d8ae1bf36bf8a79260d012f00d4d80888d1d0bb44fda16da4",
        "ecmul: 5*G");

    /* n-1: top digits force the wNAF recoding to carry into digit 256
     * (regression test for the 256- vs 257-digit bug) */
    test_scalar_mult_one(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a",
        "ecmul: (n-1)*G == -G");

    /* high bit only: long runs of zero digits */
    test_scalar_mult_one(
        "8000000000000000000000000000000000000000000000000000000000000000",
        "77b20a912e6b23135066e911891524bc4efe3560e3e92350b52dec8f375f2b54",
        "a3dc291825cea3f7f7b10bfcdd038a72df623da1e850e0f1caa801fcd6cc67ff",
        "ecmul: 2^255 * G");

    test_scalar_mult_one(
        "0000000000000001000000000000000000000000000000000000000000000001",
        "4e769e7672c9ddad31855f7db8c7fedb74e02f080203a56b2df48c04677c8a3e",
        "42b99082de8306631ec0057206947281fb9ae16f3b9122a5a4c36165b824bbb0",
        "ecmul: (2^192+1)*G (sparse scalar)");
}

/* ---------- P-256 point arithmetic ---------- */

static void test_point_arith(void) {
    ec_point_t twoG, threeG, fourG, R;

    /* doubling produces a Jacobian point with Z != 1; feed those back in
     * to exercise the general-Z addition path */
    ec_double_point(&secp256r1, &secp256r1.G, &twoG);
    check(point_eq_affine(&twoG,
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"),
        "ecadd: double(G) == 2G");

    ec_add_point(&secp256r1, &twoG, &secp256r1.G, &threeG);
    check(point_eq_affine(&threeG,
        "5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c",
        "8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032"),
        "ecadd: 2G + G == 3G (mixed Z)");

    /* same point, same representation: must detect doubling via H==0, r==0 */
    ec_add_point(&secp256r1, &twoG, &twoG, &fourG);
    check(point_eq_affine(&fourG,
        "e2534a3532d08fbba02dde659ee62bd0031fe2db785596ef509302446b030852",
        "e0f1575a4c633cc719dfee5fda862d764efc96c3f30ee0055c42c23f184ed8c6"),
        "ecadd: 2G + 2G == 4G (doubling detection)");

    /* same affine point, different Jacobian representation */
    {
        ec_point_t twoG_alt = point(
            "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
            "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1");
        ec_add_point(&secp256r1, &twoG, &twoG_alt, &R);
        check(point_eq_affine(&R,
            "e2534a3532d08fbba02dde659ee62bd0031fe2db785596ef509302446b030852",
            "e0f1575a4c633cc719dfee5fda862d764efc96c3f30ee0055c42c23f184ed8c6"),
            "ecadd: 2G(Z!=1) + 2G(Z==1) == 4G (different representations)");
    }

    /* P + (-P) == infinity */
    {
        ec_point_t negG, inf;
        ec_negate_point(&secp256r1, &secp256r1.G, &negG);
        ec_add_point(&secp256r1, &secp256r1.G, &negG, &inf);
        check(inf.infinity == 1, "ecadd: G + (-G) == infinity");
    }

    /* identity handling */
    {
        ec_point_t inf, R2;
        memset(&inf, 0, sizeof(inf));
        inf.infinity = 1;
        ec_add_point(&secp256r1, &secp256r1.G, &inf, &R2);
        check(point_eq_affine(&R2,
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
            "ecadd: G + infinity == G");
        ec_add_point(&secp256r1, &inf, &secp256r1.G, &R2);
        check(point_eq_affine(&R2,
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
            "ecadd: infinity + G == G");
    }

    check(ec_point_on_curve(&secp256r1, &twoG), "oncurve: Jacobian 2G accepted");
    {
        ec_point_t bad = point(
            "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
            "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d2");
        check(!ec_point_on_curve(&secp256r1, &bad), "oncurve: off-curve point rejected");
    }
}

/* ---------- ECDH (NIST CAVP ECC CDH, P-256, vector 0) ---------- */

#define CAVP_D    "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534"
#define CAVP_QX   "ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230"
#define CAVP_QY   "28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141"
#define CAVP_PEER_X "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287"
#define CAVP_PEER_Y "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac"
#define CAVP_Z    "46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b"

static void test_ecdh(void) {
    uint256_t d = u256(CAVP_D);
    ec_point_t peer = point(CAVP_PEER_X, CAVP_PEER_Y);

    /* public key derivation: Q = d*G */
    {
        ec_point_t Q;
        ec_scalar_multiply(&secp256r1, &d, &secp256r1.G, &Q);
        check(point_eq_affine(&Q, CAVP_QX, CAVP_QY), "ecdh: CAVP public key d*G");
    }

    /* shared x-coordinate: Z = (d * Qpeer).x */
    {
        ec_point_t S;
        uint256_t z_expected = u256(CAVP_Z);
        ec_scalar_multiply(&secp256r1, &d, &peer, &S);
        ec_jacobian_to_affine(&secp256r1, &S, &S);
        check(!S.infinity && u256_eq(&S.x, &z_expected), "ecdh: CAVP shared secret Z");
    }

    /* full API: derived keys (expected values computed independently from Z
     * with HKDF-SHA256, info "encryption"/"authentication") */
    {
        uint8_t enc[32], mac[32], expected[32];
        check(ec3dh_compute_shared_secret_dk(&secp256r1, &d, &peer, enc, 32, mac, 32) == 0,
              "ecdh: compute_shared_secret_dk succeeds");
        hex_to_bytes("82075f333c334f37afaf08d9b17b0f4a042ff7b5e237455fbadf2c93e379af91", expected, 32);
        check(memcmp(enc, expected, 32) == 0, "ecdh: derived encryption key");
        hex_to_bytes("75dc098fc58ea70796a5684fb648deb0e17f004c0b631bb3a0f54743d4a6d1c2", expected, 32);
        check(memcmp(mac, expected, 32) == 0, "ecdh: derived MAC key");
    }

    /* round trip with random keys */
    {
        uint256_t da, db;
        ec_point_t Qa, Qb;
        uint8_t ea[32], ma[32], eb[32], mb[32];
        check(ec3dh_generate_keypair(&secp256r1, &da, &Qa) == 0 &&
              ec3dh_generate_keypair(&secp256r1, &db, &Qb) == 0,
              "ecdh: keypair generation");
        ec_jacobian_to_affine(&secp256r1, &Qa, &Qa);
        ec_jacobian_to_affine(&secp256r1, &Qb, &Qb);
        check(ec3dh_compute_shared_secret_dk(&secp256r1, &da, &Qb, ea, 32, ma, 32) == 0 &&
              ec3dh_compute_shared_secret_dk(&secp256r1, &db, &Qa, eb, 32, mb, 32) == 0 &&
              memcmp(ea, eb, 32) == 0 && memcmp(ma, mb, 32) == 0,
              "ecdh: random round trip agrees");
    }
}

/* ---------- SEC1 codec ---------- */

#define G_X "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
#define G_Y "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
#define G3_X "5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c"
#define G3_Y "8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032"

static void test_codec(void) {
    uint8_t buf[65], expected[65];
    ec_point_t P;

    /* uncompressed encode: 0x04 || Gx || Gy */
    expected[0] = 0x04;
    hex_to_bytes(G_X, expected + 1, 32);
    hex_to_bytes(G_Y, expected + 33, 32);
    check(ec_point_to_bytes(&secp256r1, &secp256r1.G, 0, buf, sizeof(buf)) == 65 &&
          memcmp(buf, expected, 65) == 0,
          "codec: encode G uncompressed");

    check(ec_point_from_bytes(&secp256r1, buf, 65, &P) == 0 &&
          point_eq_affine(&P, G_X, G_Y),
          "codec: decode G uncompressed");

    /* compressed: G has odd y -> 0x03 prefix */
    check(ec_point_to_bytes(&secp256r1, &secp256r1.G, 1, buf, sizeof(buf)) == 33 &&
          buf[0] == 0x03,
          "codec: encode G compressed (odd y, prefix 03)");
    check(ec_point_from_bytes(&secp256r1, buf, 33, &P) == 0 &&
          point_eq_affine(&P, G_X, G_Y),
          "codec: decode G compressed");

    /* 3G has even y -> 0x02 prefix */
    {
        ec_point_t threeG = point(G3_X, G3_Y);
        check(ec_point_to_bytes(&secp256r1, &threeG, 1, buf, sizeof(buf)) == 33 &&
              buf[0] == 0x02,
              "codec: encode 3G compressed (even y, prefix 02)");
        check(ec_point_from_bytes(&secp256r1, buf, 33, &P) == 0 &&
              point_eq_affine(&P, G3_X, G3_Y),
              "codec: decode 3G compressed");
    }

    /* Jacobian input (Z != 1) encodes to the same bytes as its affine form */
    {
        ec_point_t twoG;
        uint8_t buf2[65];
        ec_double_point(&secp256r1, &secp256r1.G, &twoG); /* Jacobian, Z != 1 */
        ec_point_t twoG_affine = point(
            "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
            "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1");
        check(ec_point_to_bytes(&secp256r1, &twoG, 0, buf, sizeof(buf)) == 65 &&
              ec_point_to_bytes(&secp256r1, &twoG_affine, 0, buf2, sizeof(buf2)) == 65 &&
              memcmp(buf, buf2, 65) == 0,
              "codec: Jacobian and affine 2G encode identically");
    }

    /* rejections */
    {
        ec_point_t inf;
        memset(&inf, 0, sizeof(inf));
        inf.infinity = 1;
        check(ec_point_to_bytes(&secp256r1, &inf, 0, buf, sizeof(buf)) < 0,
              "codec: refuse to encode infinity");
        check(ec_point_to_bytes(&secp256r1, &secp256r1.G, 0, buf, 64) < 0,
              "codec: refuse short output buffer");
    }
    {
        uint8_t bad[65];
        ec_point_to_bytes(&secp256r1, &secp256r1.G, 0, bad, sizeof(bad));
        bad[0] = 0x05;
        check(ec_point_from_bytes(&secp256r1, bad, 65, &P) < 0, "codec: reject bad prefix");
        bad[0] = 0x04;
        check(ec_point_from_bytes(&secp256r1, bad, 64, &P) < 0, "codec: reject bad length");

        /* x == p (out of range) */
        bad[0] = 0x04;
        hex_to_bytes("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                     bad + 1, 32);
        hex_to_bytes(G_Y, bad + 33, 32);
        check(ec_point_from_bytes(&secp256r1, bad, 65, &P) < 0, "codec: reject x >= p");

        /* in-range but off-curve */
        bad[0] = 0x04;
        hex_to_bytes(G_X, bad + 1, 32);
        hex_to_bytes("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f6",
                     bad + 33, 32);
        check(ec_point_from_bytes(&secp256r1, bad, 65, &P) < 0, "codec: reject off-curve point");

        /* compressed x whose rhs is a quadratic non-residue (x = 1) */
        bad[0] = 0x02;
        hex_to_bytes("0000000000000000000000000000000000000000000000000000000000000001",
                     bad + 1, 32);
        check(ec_point_from_bytes(&secp256r1, bad, 33, &P) < 0,
              "codec: reject compressed non-residue x");
    }

    /* scalar round trip and range checks */
    {
        uint8_t sb[32];
        uint256_t k = u256(CAVP_D), k2;
        ec_scalar_to_bytes(&k, sb);
        check(ec_scalar_from_bytes(&secp256r1, sb, &k2) == 0 && u256_eq(&k, &k2),
              "codec: scalar round trip");

        memset(sb, 0, 32);
        check(ec_scalar_from_bytes(&secp256r1, sb, &k2) < 0, "codec: reject scalar 0");

        ec_scalar_to_bytes(&secp256r1.n, sb);
        check(ec_scalar_from_bytes(&secp256r1, sb, &k2) < 0, "codec: reject scalar n");

        hex_to_bytes("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
                     sb, 32); /* n - 1 */
        check(ec_scalar_from_bytes(&secp256r1, sb, &k2) == 0, "codec: accept scalar n-1");
    }

    /* full byte-level exchange: generate, export, import, agree */
    {
        uint256_t da, db;
        ec_point_t Qa, Qb, Qa_in, Qb_in;
        uint8_t pa[65], pb[33];
        uint8_t ea[32], ma[32], eb[32], mb[32];
        int ok = ec3dh_generate_keypair(&secp256r1, &da, &Qa) == 0 &&
                 ec3dh_generate_keypair(&secp256r1, &db, &Qb) == 0 &&
                 ec_point_to_bytes(&secp256r1, &Qa, 0, pa, sizeof(pa)) == 65 &&
                 ec_point_to_bytes(&secp256r1, &Qb, 1, pb, sizeof(pb)) == 33 &&
                 ec_point_from_bytes(&secp256r1, pa, 65, &Qa_in) == 0 &&
                 ec_point_from_bytes(&secp256r1, pb, 33, &Qb_in) == 0 &&
                 ec3dh_compute_shared_secret_dk(&secp256r1, &da, &Qb_in, ea, 32, ma, 32) == 0 &&
                 ec3dh_compute_shared_secret_dk(&secp256r1, &db, &Qa_in, eb, 32, mb, 32) == 0 &&
                 memcmp(ea, eb, 32) == 0 && memcmp(ma, mb, 32) == 0;
        check(ok, "codec: full serialized key exchange agrees");
    }
}

/* ---------- negative tests ---------- */

static void test_rejections(void) {
    ec_point_t peer = point(CAVP_PEER_X, CAVP_PEER_Y);
    uint8_t enc[32], mac[32];

    /* private key = 0 */
    {
        uint256_t zero;
        memset(&zero, 0, sizeof(zero));
        check(ec3dh_compute_shared_secret_dk(&secp256r1, &zero, &peer, enc, 32, mac, 32)
                  == EC3DH_ERR_PRIVKEY_RANGE,
              "reject: private key 0");
    }

    /* private key = n */
    {
        uint256_t n = secp256r1.n;
        check(ec3dh_compute_shared_secret_dk(&secp256r1, &n, &peer, enc, 32, mac, 32)
                  == EC3DH_ERR_PRIVKEY_RANGE,
              "reject: private key n");
    }

    /* off-curve peer public key */
    {
        uint256_t d = u256(CAVP_D);
        ec_point_t bad = point(CAVP_PEER_X,
            "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ad");
        check(ec3dh_compute_shared_secret_dk(&secp256r1, &d, &bad, enc, 32, mac, 32)
                  == EC3DH_ERR_PUBKEY_INVALID,
              "reject: off-curve peer pubkey");
    }

    /* peer public key = point at infinity */
    {
        uint256_t d = u256(CAVP_D);
        ec_point_t inf;
        memset(&inf, 0, sizeof(inf));
        inf.infinity = 1;
        check(ec3dh_compute_shared_secret_dk(&secp256r1, &d, &inf, enc, 32, mac, 32)
                  == EC3DH_ERR_PUBKEY_INVALID,
              "reject: peer pubkey at infinity");
    }
}

int main(void) {
    test_sha256();
    test_hmac();
    test_hkdf();
    test_scalar_mult();
    test_point_arith();
    test_ecdh();
    test_codec();
    test_rejections();

    printf("\n%d/%d tests passed\n", tests_run - tests_failed, tests_run);
    return tests_failed ? 1 : 0;
}
