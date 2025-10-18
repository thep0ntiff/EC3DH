#include "ec.h"
#include "curve_params.h"
#include "pk.h"

#include <stdio.h>


ec_point_t P;


int main(void) {
    
    uint8_t buf[32];
    pk_getrandom_bytes(buf, 32, 0);

    P.x = secp256r1.G[0];
    P.y = secp256r1.G[1];
    P.infinity = 0;
    
    

    ec_point_t R;
    ec_add_point(&secp256r1, &P, &P, &R);
    int p_on_curve = ec_point_on_curve(&secp256r1, &P);
    printf("P: %d\n", p_on_curve);
    int r_on_curve = ec_point_on_curve(&secp256r1, &R);
    printf("R: %d\n", r_on_curve);
}
