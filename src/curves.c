/*
 * curve_params.c
 * Author: Vincent Paul
 *
 * The byteorder is LSB first for the entire file
*/

#include "ec.h"

const ec_domain_params_t secp256r1 = {
    .p = { .limb = { 
        0xffffffffffffffffULL,
        0x00000000ffffffffULL,
        0x0000000000000000ULL,
        0xffffffff00000001ULL
    }},
    .a = { .limb = { 
        0xfffffffffffffffcULL, 
        0x00000000ffffffffULL,
        0x0000000000000000ULL,
        0xffffffff00000001ULL  
    }},
    .b = { .limb = { 
        0x3bce3c3e27d2604bULL,
        0x651d06b0cc53b0f6ULL,
        0xb3ebbd55769886bcULL,
        0x5ac635d8aa3a93e7ULL
    }},
    .G = {
        { .limb = { 
            0xf4a13945d898c296ULL, //Gx
            0x77037d812deb33a0ULL,
            0xf8bce6e563a440f2ULL,
            0x6b17d1f2e12c4247ULL
        }},
        { .limb = { 
            0xcbb6406837bf51f5ULL, // Gy
            0x2bce33576b315eceULL,
            0x8ee7eb4a7c0f9e16ULL,
            0x4fe342e2fe1a7f9bULL 
        }}
    },
    .n = { .limb = { 
        0xf3b9cac2fc632551ULL,
        0xbce6faada7179e84ULL,
        0xffffffffffffffffULL,
        0xffffffff00000000ULL
    }},
    .h = 2
};
