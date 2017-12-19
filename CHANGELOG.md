# CHANGELOG

## v2.1.1

A mistake was made in generating prebuilds for v2.1.0, this version resolves the
issue.

## v2.1.0
- Upgrade to libsodium 1.0.16
- Expose the new `crypto_secretstream` API
- Expose `crypto_kx` API
- Expose `sodium_pad` and `sodium_unpad` APIs
- Expose `crypto_pwhash_str_needs_rehash`
- Expose `randombytes_SEEDBYTES` `randombytes_random`, `randombytes_uniform` and
  `randombytes_buf_deterministic`
- Check for `NULL` on `sodium_malloc`
- All "Secure Buffers" (created with `sodium_malloc`) now have an immutable
  `.secure = true` property
