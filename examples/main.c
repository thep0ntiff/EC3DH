#include "ec.h"
#include "curve_params.h"
#include "pk.h"
#include "ec3dh.h"

#include <stdio.h>



int main(void) {
    
    uint256_t k = {{0}};
    
    
    ec_point_t pubkey = {0};
    ec3dh_generate_keypair(&secp256r1, &k, &pubkey);
    printf("Private key/scalar: ");
    for (int i = 0; i < 4; i++) {
        printf("%016lx", k.limb[i]);
    }
    printf("\nPublic key: \n x: ");
    for (int i = 0; i < 4; i++) {
        printf("%016lx", pubkey.x.limb[i]);
    }
    printf("\n y: ");
    for (int i = 0; i < 4; i++) {
        printf("%016lx", pubkey.y.limb[i]);
    }
    int pubkey_on_curve = ec_point_on_curve(&secp256r1, &pubkey);
    printf("\nOn curve? %d\n", pubkey_on_curve);

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
    
    
    uint256_t alice_privatekey, bob_privatekey = {0};
    ec_point_t alice_pubkey, bob_pubkey = {0};
    uint256_t alice_shared, bob_shared = {0};

    ec3dh_generate_keypair(&secp256r1, &alice_privatekey, &alice_pubkey);
    ec3dh_generate_keypair(&secp256r1, &bob_privatekey, &bob_pubkey);

    printf("Alice's public key:\n x: ");
    for (int i = 0; i < 4; i++) {
        printf("%016lx", alice_pubkey.x.limb[i]);
    }
    printf("\n y: ");
    for (int i = 0; i < 4; i++) {
        printf("%016lx", alice_pubkey.y.limb[i]);
    }
    printf("\n\n");

    printf("Bob's public key:\n x: ");
    for (int i = 0; i < 4; i++) {
        printf("%016lx", bob_pubkey.x.limb[i]);
    }
    printf("\n y: ");
    for (int i = 0; i < 4; i++) {
        printf("%016lx", bob_pubkey.y.limb[i]);
    }
    printf("\n\n");

    ec3dh_compute_shared_secret(&secp256r1, &alice_privatekey, &bob_pubkey, &alice_shared);
    ec3dh_compute_shared_secret(&secp256r1, &bob_privatekey, &alice_pubkey, &bob_shared);

    printf("\nAlice's shared secret: ");
    for (int i = 0; i < 4; i++) {
        printf("%016lx", alice_shared.limb[i]);
    }
    
    printf("\nBob's shared secret:   ");
    for (int i = 0; i < 4; i++) {
        printf("%016lx", bob_shared.limb[i]);
    }
    printf("\n");

    return 0;
}
