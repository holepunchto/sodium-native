# CHANGELOG

## Current

## v2.4.5

* node-gyp-build was accidentally added as a dev dependency.

## v2.4.4

* Fix issue with node-gyp using the node 6.0.0 headers for electron 6.0.0 when prebuilding

## v2.4.3

* Add Node 12 and Electron 5 support (thanks @davedoesdev)

## v2.4.2

* Do travis release on `lts/*` node version

## v2.4.1

* We cannot yet support Node 12 or Electron 5, so explicit versions on prebuildify.

## v2.4.0

* Fix documentation error (thanks @jedisct1)
* Add `crypto_pwhash_scryptsalsa208sha256_*` functions and constants.

## v2.3.0

* Upgrade to libsodium 1.0.17
* Add new `sodium_sub` (opposite of `sodium_add`)
* Add new finite field operations `crypto_core_ed25519_*` and constants
* Add `crypto_sign_ed25519_sk_to_pk`

## v2.2.6

* Rebuilding the electron prebuild to get 4.0.4 support to work. This has a fix
  for an ABI mismatch.

## v2.2.5

* Rebuilding the electron prebuild to get 4.0.0 support to work.

## v2.2.4

* Updated cross-references to libsodium documentation (thanks @stripedpajamas)
* Fix documentation typo (thanks @ralphtheninja)
* Fix [DEP0005] DeprecationWarning: `Buffer()` (thanks @ralphtheninja)
* Upgrade and be compliant with standard@12
* Improve robustness of Windows builds. This means that we now use the "best"
  possible MSBuild. Thank you for all the work @enko
* Due to the previous effort we can now build all artefacts on Travis and their
  new Windows offering
* Amend the new MSBuild finding algorithm to look for "Program Files (x86)"
  first, such that cross-compiling works

## v2.2.3

* Add Node 11 to build matrix

## v2.2.2

* Document release process
* Wrong error messages wrt. `crypto_sign`. Thanks @jackschmidt
* Build for Electron v3.0.0

## v2.2.1

* Fix CHANGELOG

## v2.2.0

* Register tags for `async_hook`s on `crypto_pwhash_*_async` functions
* Add constants and methods for `crypto_aead_xchacha20poly1305_ietf_*`. Please
  note the special circumstances around the bindings of `MESSAGEBYTES_MAX` and
  `crypto_aead_xchacha20poly1305_ietf_*_detached`.
* Improved error messages; now reports the constants and argument names
  documented from javascript.
* Use `Buffer.alloc`/`Buffer.fill`/`Buffer.from` in tests and examples
* Add more libsodium helpers; `sodium_memcmp`, `sodium_compare`, `sodium_add`,
  `sodium_increment`, `sodium_is_zero`
* Make it possible to pass only one of `rx` or `tx` to `crypto_kx_*`
* Add `crypto_scalarmult_ed25519_*` and `crypto_core_ed25519_*` operations

## v2.1.6

* Additional check `x < 0` before cast on uint assert macro
* Add prebuilds for Node 10

## v2.1.5

Fixes a critical bug in `crypto_secretstream_xchacha20poly1305_init_push` where
it would call `crypto_secretstream_xchacha20poly1305_init_pull` instead.

## v2.1.4

Only use the constants that `libsodium` compiled with instead of the ones that
`sodium-native` compiled with. This has caused bugs for some users and may have
led to subtle bugs.

## v2.1.3

Rework build process so it is more versatile on UNIX operating systems by
parsing the libtool archive files for correct .so name. This fixes builds on
OpenBSD (#54)

## v2.1.2

Fix `armv7l` builds.

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
