/*
 * secure_wipe.h
 *
 * Zeroization that the compiler may not optimize away. A plain memset()
 * before a buffer goes out of scope is a dead store and can legally be
 * removed; writing through a volatile pointer forces the stores to happen.
 */

#ifndef SECURE_WIPE_H
#define SECURE_WIPE_H

#include <stddef.h>
#include <stdint.h>

static inline void secure_wipe(void *buf, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)buf;
    while (len--) {
        *p++ = 0;
    }
}

#endif /* SECURE_WIPE_H */
