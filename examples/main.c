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

}
