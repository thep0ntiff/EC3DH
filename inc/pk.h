#ifndef PK_H
#define PK_H

#include <stddef.h>
#include <unistd.h>

#if defined(__WIN32) || defined(__WIN64)
#define WINDOWS
#pragma comment(lib, "bcrypt")

#else
#define LINUX 1
#endif

ssize_t pk_getrandom_bytes(void *buf, size_t buflen, unsigned int flags);


#endif
