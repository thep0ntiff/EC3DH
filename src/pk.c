/*
 * pk.c
 * Author: Vincent Paul
 *
 * This file contains everything used for creating the private key/scalar
*/

#include "pk.h"
#include "ec.h"

#include <stdio.h>
#include <modplus.h>

#if LINUX
#define _GNU_SOURCE
#include <unistd.h>
#include <stddef.h>
#include <stddef.h>
#include <sys/random.h>
#include <errno.h>
#else


#endif


ssize_t kp_getrandom_bytes(void *buf, size_t buflen, unsigned int flags) {

    size_t off = 0;
    while (off < buflen) {
        
        ssize_t r = getrandom((char *)buf + off, buflen - off, flags);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)r;

    }
    return (ssize_t)off;
}

int kp_generate_private_key(const ec_domain_params_t *curve, uint256_t *private_key) {
    unsigned char bytes[BUFLEN];
    ssize_t result;
    int rare_event = 0;

    do {
        result = kp_getrandom_bytes(bytes, BUFLEN, 0);
        if (result < 0) {
            return -1;
        }

        for (int i = 0; i < 4; i++) {
            (*private_key).limb[i] =
                ((uint64_t)bytes[i * 8 + 7] << 0) |
                ((uint64_t)bytes[i * 8 + 6] << 8) |
                ((uint64_t)bytes[i * 8 + 5] << 16) |
                ((uint64_t)bytes[i * 8 + 4] << 24) |
                ((uint64_t)bytes[i * 8 + 3] << 32) |
                ((uint64_t)bytes[i * 8 + 2] << 40) |
                ((uint64_t)bytes[i * 8 + 1] << 48)  |
                ((uint64_t)bytes[i * 8 + 0] << 56);
        }
        if ((uint256_cmp(private_key, &curve->n) >= 0) || uint256_is_zero(private_key)) {
            rare_event = 1;
        }


    } while (uint256_cmp(private_key, &curve->n) >= 0 || uint256_is_zero(private_key));

    if (rare_event) {
        printf("\n");
        printf("╔═══════════════════════════════════════════════════════════╗\n");
        printf("║  🎰 JACKPOT! YOU HIT THE 1-IN-4.3-BILLION CASE! 🎰        ║\n");
        printf("║                                                           ║\n");
        printf("║  Generated random value exceeded curve order!             ║\n");
        printf("║  Probability: ~0.0000000233%%                             ║\n");
        printf("║                                                           ║\n");
        printf("║  Illusion appears, illusion ceases                        ║\n");
        printf("║  The biggest illusion among all is our body               ║\n");
        printf("║  Once a pacified heart finds its place                    ║\n");
        printf("║  There's no such body to look for                         ║\n");
        printf("╚═══════════════════════════════════════════════════════════╝\n");
        printf("\n");
    }

    return 0;
}
