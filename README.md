# EC3DH
Elliptic Curve Cryptography Cofactor Diffie-Hellman (ECC CDH)

Note: The current code does not use constant time algortihms and is therefore vulnerable to side-channel attacks. This might change in the near future.
      Currently, there is also no Windows support. If you want to use this on Windows, add a secure rng in the pk.c file that uses something like BCryptGenRandom().
