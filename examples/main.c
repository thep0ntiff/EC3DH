#include "ec.h"
#include "curve_params.h"
#include "pk.h"
#include "ec3dh.h"
#include "sha256.h"
#include "codec.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

static void print_hex(const char *label, const uint8_t *buf, size_t len) {
    printf("%s", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

void test_diffie_hellman_kdf() {
    uint256_t alice_priv, bob_priv;
    ec_point_t alice_pub, bob_pub;
    
    ec3dh_generate_keypair(&secp256r1, &alice_priv, &alice_pub);
    ec3dh_generate_keypair(&secp256r1, &bob_priv, &bob_pub);
    
    uint8_t alice_enc_key[32];
    uint8_t alice_mac_key[32];
    
    ec3dh_compute_shared_secret_dk(
        &secp256r1, &alice_priv, &bob_pub,
        alice_enc_key, 32,
        alice_mac_key, 32
    );
    
    uint8_t bob_enc_key[32];
    uint8_t bob_mac_key[32];
    
    ec3dh_compute_shared_secret_dk(
        &secp256r1, &bob_priv, &alice_pub,
        bob_enc_key, 32,
        bob_mac_key, 32
    );
    
    printf("Encryption keys match: %d\n", 
           memcmp(alice_enc_key, bob_enc_key, 32) == 0);
    printf("MAC keys match: %d\n",
           memcmp(alice_mac_key, bob_mac_key, 32) == 0);
    
}

void test_ecc() {

    uint256_t k = {{0}};
    
    
    ec_point_t pubkey = {0};
    uint8_t scalar_bytes[32];
    uint8_t point_bytes[EC_POINT_UNCOMPRESSED_LEN];

    ec3dh_generate_keypair(&secp256r1, &k, &pubkey);

    ec_scalar_to_bytes(&k, scalar_bytes);
    print_hex("Private key/scalar: ", scalar_bytes, sizeof(scalar_bytes));

    ec_point_to_bytes(&secp256r1, &pubkey, 0, point_bytes, sizeof(point_bytes));
    print_hex("Public key (SEC1 uncompressed): ", point_bytes, sizeof(point_bytes));

    ec_point_to_bytes(&secp256r1, &pubkey, 1, point_bytes, EC_POINT_COMPRESSED_LEN);
    print_hex("Public key (SEC1 compressed):   ", point_bytes, EC_POINT_COMPRESSED_LEN);

    int pubkey_on_curve = ec_point_on_curve(&secp256r1, &pubkey);
    printf("On curve? %d\n", pubkey_on_curve);

    ec_point_t R = {0}, R2 = {0}, R_scalar = {0};
    ec_add_point(&secp256r1, &secp256r1.G, &secp256r1.G, &R);

    int p_on_curve = ec_point_on_curve(&secp256r1, &secp256r1.G);
    printf("G: %d\n", p_on_curve);
    int r_on_curve = ec_point_on_curve(&secp256r1, &R);
    printf("R: %d\n", r_on_curve);

    ec_add_point(&secp256r1, &secp256r1.G, &R, &R2);
    int R2_on_curve = ec_point_on_curve(&secp256r1, &R2);
    printf("R2: %d\n", R2_on_curve);
    ec_scalar_multiply(&secp256r1, &k, &R, &R_scalar);
    int r_scalar_on_curve = ec_point_on_curve(&secp256r1, &R_scalar);
    printf("R_scalar: %d\n", r_scalar_on_curve);
}

void benchmark_scalar_multiply() {
    uint256_t k;
    ec_point_t result;

    kp_generate_private_key(&secp256r1, &k);

    for (int i = 0; i < 10; i++) {
        ec_scalar_multiply(&secp256r1, &k, &secp256r1.G, &result);
    }
    printf("Starting scalar multiplication benchmark...\n");
    int iterations = 1000;
    clock_t start = clock();
    for (int i = 0; i < iterations; i++) {
        ec_scalar_multiply(&secp256r1, &k, &secp256r1.G, &result);
    }
    clock_t end = clock();
    double avg_time = ((double)(end - start) / CLOCKS_PER_SEC) / iterations;
    
    printf("Average scalar multiplication: %.6f ms\n", avg_time * 1000);
    printf("Operations per second: %.0f\n", 1.0 / avg_time);
}

int main(void) {

    test_ecc();
    test_diffie_hellman_kdf();
    benchmark_scalar_multiply();
    


    return 0;
}
