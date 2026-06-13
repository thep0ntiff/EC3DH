/*
 * pk.c
 * Author: Vincent Paul
 *
 * This file contains everything used for creating the private key/scalar
*/

#if defined(__linux__)
#define _GNU_SOURCE /* must precede all includes for getrandom() */
#endif

#include "pk.h"
#include "ec.h"
#include "secure_wipe.h"

#include <string.h>
#include <modplus.h>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
// Link with bcrypt.lib: add -lbcrypt to linker flags
#pragma comment(lib, "bcrypt.lib")
#elif defined(__APPLE__)
#include <sys/random.h>
#include <unistd.h>
#else
#include <unistd.h>
#include <stddef.h>
#include <sys/random.h>
#include <errno.h>
#endif


ssize_t kp_getrandom_bytes(void *buf, size_t buflen, unsigned int flags) {
#if defined(_WIN32)
    (void)flags;
    NTSTATUS status = BCryptGenRandom(
        NULL,
        (PUCHAR)buf,
        (ULONG)buflen,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    if (!BCRYPT_SUCCESS(status)) {
        return -1;
    }

    return (ssize_t)buflen;
#elif defined(__APPLE__)
    (void)flags;
    size_t off = 0;
    while (off < buflen) {
        /* getentropy() is limited to 256 bytes per call */
        size_t chunk = buflen - off;
        if (chunk > 256) chunk = 256;
        if (getentropy((char *)buf + off, chunk) != 0) {
            secure_wipe(buf, buflen);
            return -1;
        }
        off += chunk;
    }
    return (ssize_t)off;
#else
    size_t off = 0;
    while (off < buflen) {

        ssize_t r = getrandom((char *)buf + off, buflen - off, flags);
        if (r < 0) {
            if (errno == EINTR) continue;
            secure_wipe(buf, buflen);
            return -1;
        }
        off += (size_t)r;

    }
    return (ssize_t)off;
#endif
}

int kp_generate_private_key(const ec_domain_params_t *curve, uint256_t *private_key) {
    unsigned char bytes[BUFLEN];
    ssize_t result;

    do {
        result = kp_getrandom_bytes(bytes, BUFLEN, 0);
        if (result < 0) {
            secure_wipe(bytes, BUFLEN);
            secure_wipe(private_key, sizeof(*private_key));
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

    } while (uint256_cmp(private_key, &curve->n) >= 0 || uint256_is_zero(private_key));

    secure_wipe(bytes, BUFLEN);

    return 0;
}
