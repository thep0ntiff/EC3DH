/*
 * pk.c
 * Author: Vincent Paul
 *
 * This file contains everything used for creating the private key/scalar
*/

#include "pk.h"

#include <stdio.h>

#if LINUX
#define _GNU_SOURCE
#include <unistd.h>
#include <stddef.h>
#include <stddef.h>
#include <sys/random.h>
#include <errno.h>
#else


#endif


ssize_t pk_getrandom_bytes(void *buf, size_t buflen, unsigned int flags) {

    size_t off = 0;
    while (off < buflen) {
        
        ssize_t r = getrandom((char *)buf + off, buflen - off, flags);
        if (r < 0) {
            if (errno = EINTR) continue;
            return -1;
        }
        off += (size_t)r;
                
    }
    unsigned char *b = (unsigned char *)buf;
    printf("Random bytes:\n");
    for (size_t i = 0; i < buflen; i++) {
        printf("%02x", b[i]);
    }
    printf("\n");
    return (ssize_t)off;
}

