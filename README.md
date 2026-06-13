# EC3DH
Elliptic Curve Cryptography Cofactor Diffie-Hellman (ECC CDH)

## Status

- Scalar multiplication uses a fixed-length wNAF ladder built on the
  complete addition formulas of Renes-Costello-Batina (EUROCRYPT 2016),
  with constant-time table lookups and conditional negation. There is no
  secret-dependent branching at the group-operation level.
- **Caveat:** true constant-time behavior also depends on the underlying
  field arithmetic (`mod_mul`, `mod_inv`, ... from libmodplus), which has
  not been verified to be constant time. Treat side-channel resistance as
  best-effort until that is audited (e.g. with dudect or ctgrind).
- The curve cofactor is assumed to be 1 (true for secp256r1, the only
  built-in curve); there is no explicit multiply-by-h step.

## Usage

Keys and points cross the API boundary as bytes (see `inc/codec.h`):
points use SEC1 encoding (65-byte uncompressed `04 || X || Y` or 33-byte
compressed `02/03 || X`), scalars are 32-byte big-endian. Decoding
validates lengths, coordinate ranges and curve membership.

The library never prints; all functions report failures through return
codes (see the `EC3DH_ERR_*` values in `inc/ec3dh.h`).

## Building and testing

```
make            # build libec + example
make test       # build and run the known-answer test suite (tests/kat.c)
```

The test suite covers SHA-256 (FIPS 180-4), HMAC (RFC 4231), HKDF
(RFC 5869), P-256 scalar multiplication and point arithmetic, ECDH
(NIST CAVP component test), the SEC1 codec, and input-validation
rejection paths.

## Platform support

Key generation uses `getrandom()` on Linux, `getentropy()` on macOS and
`BCryptGenRandom()` on Windows. Linux is the primary tested platform.
