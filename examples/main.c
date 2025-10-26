#include "ec.h"
#include "curve_params.h"
#include "pk.h"

#include <stdio.h>


ec_point_t P;


int main(void) {
    
    uint256_t k;
    if (pk_generate_private_key(&secp256r1, &k)) {
        return 1;
    }
    for (int i = 0; i < 4; i++) {
        printf("%016lx", k.limb[i]);
    }
    printf("\n");


    P.x = secp256r1.G[0];
    P.y = secp256r1.G[1];
    P.infinity = 0;
    

    ec_point_t R = {0}, R2 = {0}, R_scalar = {0};
    ec_add_point(&secp256r1, &P, &P, &R);

    int p_on_curve = ec_point_on_curve(&secp256r1, &P);
    printf("P: %d\n", p_on_curve);
    int r_on_curve = ec_point_on_curve(&secp256r1, &R);
    printf("R: %d\n", r_on_curve);

    ec_add_point(&secp256r1, &P, &R, &R2);
    int R2_on_curve = ec_point_on_curve(&secp256r1, &R2);
    printf("R2: %d\n", R2_on_curve);
    ec_scalar_multiply(&secp256r1, &k, &R, &R_scalar);
    int r_scalar_on_curve = ec_point_on_curve(&secp256r1, &R_scalar);
    printf("R_scalar: %d\n", r_scalar_on_curve);
}
