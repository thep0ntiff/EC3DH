/*
 * codec.h
 *
 * Byte-oriented import/export for points and scalars, so library users
 * never have to touch uint256_t limb order.
 *
 * Points use SEC1 encoding, big-endian coordinates:
 *   uncompressed: 0x04 || X || Y                (65 bytes)
 *   compressed:   0x02/0x03 || X  (parity of Y) (33 bytes)
 *
 * Scalars are 32-byte big-endian integers.
 *
 * Decoding performs full validation: length/prefix checks, coordinate
 * range checks (x, y < p), and curve membership. Decoded points are
 * returned in affine form (z == 1). The point at infinity is never a
 * valid encoding.
 */

#ifndef CODEC_H
#define CODEC_H

#include "ec.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EC_POINT_UNCOMPRESSED_LEN 65
#define EC_POINT_COMPRESSED_LEN   33

/* Encode P (affine or Jacobian) into out. Set compressed to select the
 * 33-byte form. out_len must be at least the size of the chosen form.
 * Returns the number of bytes written, or -1 on error (infinity,
 * buffer too small). */
int ec_point_to_bytes(const ec_domain_params_t *curve, const ec_point_t *P,
                      int compressed, uint8_t *out, size_t out_len);

/* Decode and validate a SEC1 point. Accepts the 65-byte uncompressed and
 * 33-byte compressed forms. Returns 0 on success, -1 if the encoding is
 * malformed, a coordinate is out of range, or the point is not on the
 * curve. Compressed decoding requires p == 3 (mod 4). */
int ec_point_from_bytes(const ec_domain_params_t *curve,
                        const uint8_t *in, size_t in_len, ec_point_t *P);

/* Encode a scalar as 32 big-endian bytes. */
void ec_scalar_to_bytes(const uint256_t *k, uint8_t out[32]);

/* Decode a 32-byte big-endian scalar and check it lies in [1, n-1].
 * Returns 0 on success, -1 if out of range. */
int ec_scalar_from_bytes(const ec_domain_params_t *curve,
                         const uint8_t in[32], uint256_t *k);

#ifdef __cplusplus
}
#endif

#endif /* CODEC_H */
