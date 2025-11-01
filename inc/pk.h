#ifndef PK_H
#define PK_H

#include "ec.h"

#include <stddef.h>
#include <unistd.h>
#include <modplus.h>

#if defined(__WIN32) || defined(__WIN64)
#define WINDOWS
#pragma comment(lib, "bcrypt")

#else
#define LINUX 1
#endif

#define BUFLEN 32

ssize_t kp_getrandom_bytes(void *buf, size_t buflen, unsigned int flags);
int kp_generate_private_key(const ec_domain_params_t *curve, uint256_t *private_key);


#endif
