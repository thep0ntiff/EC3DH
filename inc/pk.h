#ifndef PK_H
#define PK_H

#include "ec.h"

#include <stddef.h>
#include <modplus.h>

#if defined(_WIN32)
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#else
#include <unistd.h>
#endif

#define BUFLEN 32

#ifdef __cplusplus
extern "C" {
#endif

ssize_t kp_getrandom_bytes(void *buf, size_t buflen, unsigned int flags);
int kp_generate_private_key(const ec_domain_params_t *curve, uint256_t *private_key);

#ifdef __cplusplus
}
#endif

#endif
