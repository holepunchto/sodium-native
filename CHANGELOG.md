# CHANGELOG

## Current

## v4.2.1
* Move to cmake for building.

## v4.2.0
* Adds prebuilds for android, ios, and windows/linux arm64.

## v4.1.1
* Missing extensions folder in build when building from source.

## v4.1.0
* Refactor extensions into an `extension_*` namespace for clarity on the exports.
* Add `pbkdf2` extension
* async operations return promises, whilst maintaining callback compat. Callbacks scheduled for removal in v5.

## v4.0.10
* Revert back to a static build for CMAKE.

## v4.0.9
* With CMAKE only link the objects.

## v4.0.8
* Fix pkg.addon to be just the boolean.

## v4.0.7
* Add pkg.addon.target to explicitly know the CMAKE target.

## v4.0.6
* Fix CMAKE flag for Windows.

## v4.0.5
* Upgrade prebuildify to make named prebuilds.

## v4.0.4
* Fix cmake file

## v4.0.3
* Added missing cmake files.

## v4.0.2
* Move build to support iOS/Android also.

## v4.0.1
* Remove unneeded asserts. Also fixes an issue where they would get compiled out.

## v4.0.0
* crypto_secretstream_xchacha20poly1305_push accepts an int instead of a buffer for the tag param.
* crypto_secretstream_xchacha20poly1305_TAG_MESSAGE is now an int.
* crypto_secretstream_xchacha20poly1305_TAG_PUSH is now an int.
* crypto_secretstream_xchacha20poly1305_TAG_REKEY is now an int.
* crypto_secretstream_xchacha20poly1305_TAG_FINAL is not an int.
* Move to 1.0.18-stable instead of fixed 1.0.18 for easier build.
* Fix memleak in secure buffers.
* Moved to uv workers instead of n-api ones for async methods.
* musl prebuilds (for alpine linux).
* Update experimental tweak api.

## v3.4.1
* Fixed intel prebuild to still support sse (performance enhancement)

## v3.4.0
* Added experimental key tweaking api for signing.

## v3.3.0
* Moved to a static build to reduce build complexity and allow more platforms for our prebuilds.

## v3.2.1
* Normalised and typo fixed error messages (Thanks @martinheidegger)

## v3.2.0
* Add missing `napi` prototype for Node v10
* Make "missing" checks behave like Javascript (`x == null`)
* Typo in error message (Thanks @christianbundy)
* Add missing `crypto_stream_xchacha20_*` `crypto_stream_salsa20_*` APIs

## v3.1.1

* Bump `prebuildify`. Electron no longer needs a custom napi build

## v3.1.0

* Add explicit `sodium.sodium_free(buf)` to free the memory backed by a secure
buffer. This uses the detach semantics known from `.transfer` in the browser and
from Node worker threads. This is a no-op on older versions of Node and is
currently pending backporting to Node 10.x
* External memory book-keeping. For every secure buffer we now increment the
external memory of node by 16 kb to better hint the garbage collector about the
true consumption of secure buffers. This is not exactly representative if more
than a page of system memory is allocated by the user nor if the system page
size is not 4kb.
* Throw an exception of `sodium_malloc` returns a NULL pointer (eg unable to
allocate secure memory).
* Expose new APIs and associated constants: `crypto_stream_chacha20`,
`crypto_stream_chacha20_ietf`, `crypto_aead_chacha20`, `crypto_aead_chacha20_ietf`,
* Expose `crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX`, `crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX` and `crypto_aead_chacha20poly1305_MESSAGEBYTES_MAX` as `BigInt`s

## v3.0.1

* Fixed an issue that caused an assert error if an async callback threw an exception.

## v3.0.0

* Updated to use n-api (@chm-diederichs).
* Removed object instance apis and replaced them with init, update, final methods.
* Bumped dev dependencies.
* Bumped libsodium to 1.0.18.

## v2.4.10

* Prebuilds for Electron 8

## v2.4.9

* Downgrades npm on travis to 6.11.x as we cannot build prebuilds with node-gyp@5.0.5. Can be upgraded again when npm ships node-gyp@6.

## v2.4.8

* Removing Node 4 and 6 from Travis as the config does not work there. We still build for 4 and 6 though.

## v2.4.7

* Prebuilds for Node 13 and new Electron

## v2.4.6

* Prebuildify fixes

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
