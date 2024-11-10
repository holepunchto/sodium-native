cmake_minimum_required(VERSION 3.25)

find_package(cmake-bare REQUIRED PATHS node_modules/cmake-bare)
find_package(cmake-fetch REQUIRED PATHS node_modules/cmake-fetch)
find_package(cmake-napi REQUIRED PATHS node_modules/cmake-napi)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

project(sodium_native C ASM)

fetch_package("github:jedisct1/libsodium#1.0.20-RELEASE" SOURCE_DIR sodium)

include(TestBigEndian)

bare_target(target)

find_program(node NAMES node REQUIRED)

add_custom_command(
  COMMAND ${node} scripts/version.js ${sodium}
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  OUTPUT
    ${sodium}/src/libsodium/include/sodium/version.h
  DEPENDS
    ${sodium}/src/libsodium/include/sodium/version.h.in
  VERBATIM
)

add_library(sodium OBJECT)

target_sources(
  sodium
  INTERFACE
    ${sodium}/src/libsodium/crypto_aead/aegis128l/aegis128l_aesni.h
    ${sodium}/src/libsodium/crypto_aead/aegis128l/aegis128l_armcrypto.h
    ${sodium}/src/libsodium/crypto_aead/aegis128l/aegis128l_common.h
    ${sodium}/src/libsodium/crypto_aead/aegis128l/aegis128l_soft.h
    ${sodium}/src/libsodium/crypto_aead/aegis128l/implementations.h
    ${sodium}/src/libsodium/crypto_aead/aegis256/aegis256_aesni.h
    ${sodium}/src/libsodium/crypto_aead/aegis256/aegis256_armcrypto.h
    ${sodium}/src/libsodium/crypto_aead/aegis256/aegis256_common.h
    ${sodium}/src/libsodium/crypto_aead/aegis256/aegis256_soft.h
    ${sodium}/src/libsodium/crypto_aead/aegis256/implementations.h
    ${sodium}/src/libsodium/crypto_core/ed25519/ref10/fe_25_5/base.h
    ${sodium}/src/libsodium/crypto_core/ed25519/ref10/fe_25_5/base2.h
    ${sodium}/src/libsodium/crypto_core/ed25519/ref10/fe_25_5/constants.h
    ${sodium}/src/libsodium/crypto_core/ed25519/ref10/fe_25_5/fe.h
    ${sodium}/src/libsodium/crypto_core/ed25519/ref10/fe_51/base.h
    ${sodium}/src/libsodium/crypto_core/ed25519/ref10/fe_51/base2.h
    ${sodium}/src/libsodium/crypto_core/ed25519/ref10/fe_51/constants.h
    ${sodium}/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h
    ${sodium}/src/libsodium/crypto_generichash/blake2b/ref/blake2.h
    ${sodium}/src/libsodium/crypto_generichash/blake2b/ref/blake2b-compress-avx2.h
    ${sodium}/src/libsodium/crypto_generichash/blake2b/ref/blake2b-compress-sse41.h
    ${sodium}/src/libsodium/crypto_generichash/blake2b/ref/blake2b-compress-ssse3.h
    ${sodium}/src/libsodium/crypto_generichash/blake2b/ref/blake2b-load-avx2.h
    ${sodium}/src/libsodium/crypto_generichash/blake2b/ref/blake2b-load-sse2.h
    ${sodium}/src/libsodium/crypto_generichash/blake2b/ref/blake2b-load-sse41.h
    ${sodium}/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.h
    ${sodium}/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna32.h
    ${sodium}/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h
    ${sodium}/src/libsodium/crypto_onetimeauth/poly1305/onetimeauth_poly1305.h
    ${sodium}/src/libsodium/crypto_onetimeauth/poly1305/sse2/poly1305_sse2.h
    ${sodium}/src/libsodium/crypto_pwhash/argon2/argon2-core.h
    ${sodium}/src/libsodium/crypto_pwhash/argon2/argon2-encoding.h
    ${sodium}/src/libsodium/crypto_pwhash/argon2/argon2.h
    ${sodium}/src/libsodium/crypto_pwhash/argon2/blake2b-long.h
    ${sodium}/src/libsodium/crypto_pwhash/argon2/blamka-round-avx2.h
    ${sodium}/src/libsodium/crypto_pwhash/argon2/blamka-round-avx512f.h
    ${sodium}/src/libsodium/crypto_pwhash/argon2/blamka-round-ref.h
    ${sodium}/src/libsodium/crypto_pwhash/argon2/blamka-round-ssse3.h
    ${sodium}/src/libsodium/crypto_pwhash/scryptsalsa208sha256/crypto_scrypt.h
    ${sodium}/src/libsodium/crypto_pwhash/scryptsalsa208sha256/pbkdf2-sha256.h
    ${sodium}/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.h
    ${sodium}/src/libsodium/crypto_scalarmult/curve25519/sandy2x/consts_namespace.h
    ${sodium}/src/libsodium/crypto_scalarmult/curve25519/sandy2x/curve25519_sandy2x.h
    ${sodium}/src/libsodium/crypto_scalarmult/curve25519/sandy2x/fe.h
    ${sodium}/src/libsodium/crypto_scalarmult/curve25519/sandy2x/fe51.h
    ${sodium}/src/libsodium/crypto_scalarmult/curve25519/sandy2x/fe51_namespace.h
    ${sodium}/src/libsodium/crypto_scalarmult/curve25519/sandy2x/ladder.h
    ${sodium}/src/libsodium/crypto_scalarmult/curve25519/sandy2x/ladder_namespace.h
    ${sodium}/src/libsodium/crypto_scalarmult/curve25519/scalarmult_curve25519.h
    ${sodium}/src/libsodium/crypto_shorthash/siphash24/ref/shorthash_siphash_ref.h
    ${sodium}/src/libsodium/crypto_sign/ed25519/ref10/sign_ed25519_ref10.h
    ${sodium}/src/libsodium/crypto_stream/chacha20/dolbeau/chacha20_dolbeau-avx2.h
    ${sodium}/src/libsodium/crypto_stream/chacha20/dolbeau/chacha20_dolbeau-ssse3.h
    ${sodium}/src/libsodium/crypto_stream/chacha20/dolbeau/u0.h
    ${sodium}/src/libsodium/crypto_stream/chacha20/dolbeau/u1.h
    ${sodium}/src/libsodium/crypto_stream/chacha20/dolbeau/u4.h
    ${sodium}/src/libsodium/crypto_stream/chacha20/dolbeau/u8.h
    ${sodium}/src/libsodium/crypto_stream/chacha20/ref/chacha20_ref.h
    ${sodium}/src/libsodium/crypto_stream/chacha20/stream_chacha20.h
    ${sodium}/src/libsodium/crypto_stream/salsa20/ref/salsa20_ref.h
    ${sodium}/src/libsodium/crypto_stream/salsa20/stream_salsa20.h
    ${sodium}/src/libsodium/crypto_stream/salsa20/xmm6/salsa20_xmm6.h
    ${sodium}/src/libsodium/crypto_stream/salsa20/xmm6int/salsa20_xmm6int-avx2.h
    ${sodium}/src/libsodium/crypto_stream/salsa20/xmm6int/salsa20_xmm6int-sse2.h
    ${sodium}/src/libsodium/crypto_stream/salsa20/xmm6int/u0.h
    ${sodium}/src/libsodium/crypto_stream/salsa20/xmm6int/u1.h
    ${sodium}/src/libsodium/crypto_stream/salsa20/xmm6int/u4.h
    ${sodium}/src/libsodium/crypto_stream/salsa20/xmm6int/u8.h
    ${sodium}/src/libsodium/include/sodium.h
    ${sodium}/src/libsodium/include/sodium/core.h
    ${sodium}/src/libsodium/include/sodium/crypto_aead_aegis128l.h
    ${sodium}/src/libsodium/include/sodium/crypto_aead_aegis256.h
    ${sodium}/src/libsodium/include/sodium/crypto_aead_aes256gcm.h
    ${sodium}/src/libsodium/include/sodium/crypto_aead_chacha20poly1305.h
    ${sodium}/src/libsodium/include/sodium/crypto_aead_xchacha20poly1305.h
    ${sodium}/src/libsodium/include/sodium/crypto_auth.h
    ${sodium}/src/libsodium/include/sodium/crypto_auth_hmacsha256.h
    ${sodium}/src/libsodium/include/sodium/crypto_auth_hmacsha512.h
    ${sodium}/src/libsodium/include/sodium/crypto_auth_hmacsha512256.h
    ${sodium}/src/libsodium/include/sodium/crypto_box.h
    ${sodium}/src/libsodium/include/sodium/crypto_box_curve25519xchacha20poly1305.h
    ${sodium}/src/libsodium/include/sodium/crypto_box_curve25519xsalsa20poly1305.h
    ${sodium}/src/libsodium/include/sodium/crypto_core_ed25519.h
    ${sodium}/src/libsodium/include/sodium/crypto_core_hchacha20.h
    ${sodium}/src/libsodium/include/sodium/crypto_core_hsalsa20.h
    ${sodium}/src/libsodium/include/sodium/crypto_core_ristretto255.h
    ${sodium}/src/libsodium/include/sodium/crypto_core_salsa20.h
    ${sodium}/src/libsodium/include/sodium/crypto_core_salsa2012.h
    ${sodium}/src/libsodium/include/sodium/crypto_core_salsa208.h
    ${sodium}/src/libsodium/include/sodium/crypto_generichash.h
    ${sodium}/src/libsodium/include/sodium/crypto_generichash_blake2b.h
    ${sodium}/src/libsodium/include/sodium/crypto_hash.h
    ${sodium}/src/libsodium/include/sodium/crypto_hash_sha256.h
    ${sodium}/src/libsodium/include/sodium/crypto_hash_sha512.h
    ${sodium}/src/libsodium/include/sodium/crypto_kdf.h
    ${sodium}/src/libsodium/include/sodium/crypto_kdf_blake2b.h
    ${sodium}/src/libsodium/include/sodium/crypto_kdf_hkdf_sha256.h
    ${sodium}/src/libsodium/include/sodium/crypto_kdf_hkdf_sha512.h
    ${sodium}/src/libsodium/include/sodium/crypto_kx.h
    ${sodium}/src/libsodium/include/sodium/crypto_onetimeauth.h
    ${sodium}/src/libsodium/include/sodium/crypto_onetimeauth_poly1305.h
    ${sodium}/src/libsodium/include/sodium/crypto_pwhash.h
    ${sodium}/src/libsodium/include/sodium/crypto_pwhash_argon2i.h
    ${sodium}/src/libsodium/include/sodium/crypto_pwhash_argon2id.h
    ${sodium}/src/libsodium/include/sodium/crypto_pwhash_scryptsalsa208sha256.h
    ${sodium}/src/libsodium/include/sodium/crypto_scalarmult.h
    ${sodium}/src/libsodium/include/sodium/crypto_scalarmult_curve25519.h
    ${sodium}/src/libsodium/include/sodium/crypto_scalarmult_ed25519.h
    ${sodium}/src/libsodium/include/sodium/crypto_scalarmult_ristretto255.h
    ${sodium}/src/libsodium/include/sodium/crypto_secretbox.h
    ${sodium}/src/libsodium/include/sodium/crypto_secretbox_xchacha20poly1305.h
    ${sodium}/src/libsodium/include/sodium/crypto_secretbox_xsalsa20poly1305.h
    ${sodium}/src/libsodium/include/sodium/crypto_secretstream_xchacha20poly1305.h
    ${sodium}/src/libsodium/include/sodium/crypto_shorthash.h
    ${sodium}/src/libsodium/include/sodium/crypto_shorthash_siphash24.h
    ${sodium}/src/libsodium/include/sodium/crypto_sign.h
    ${sodium}/src/libsodium/include/sodium/crypto_sign_ed25519.h
    ${sodium}/src/libsodium/include/sodium/crypto_sign_edwards25519sha512batch.h
    ${sodium}/src/libsodium/include/sodium/crypto_stream.h
    ${sodium}/src/libsodium/include/sodium/crypto_stream_chacha20.h
    ${sodium}/src/libsodium/include/sodium/crypto_stream_salsa20.h
    ${sodium}/src/libsodium/include/sodium/crypto_stream_salsa2012.h
    ${sodium}/src/libsodium/include/sodium/crypto_stream_salsa208.h
    ${sodium}/src/libsodium/include/sodium/crypto_stream_xchacha20.h
    ${sodium}/src/libsodium/include/sodium/crypto_stream_xsalsa20.h
    ${sodium}/src/libsodium/include/sodium/crypto_verify_16.h
    ${sodium}/src/libsodium/include/sodium/crypto_verify_32.h
    ${sodium}/src/libsodium/include/sodium/crypto_verify_64.h
    ${sodium}/src/libsodium/include/sodium/export.h
    ${sodium}/src/libsodium/include/sodium/private/asm_cet.h
    ${sodium}/src/libsodium/include/sodium/private/chacha20_ietf_ext.h
    ${sodium}/src/libsodium/include/sodium/private/common.h
    ${sodium}/src/libsodium/include/sodium/private/ed25519_ref10.h
    ${sodium}/src/libsodium/include/sodium/private/ed25519_ref10_fe_25_5.h
    ${sodium}/src/libsodium/include/sodium/private/ed25519_ref10_fe_51.h
    ${sodium}/src/libsodium/include/sodium/private/implementations.h
    ${sodium}/src/libsodium/include/sodium/private/mutex.h
    ${sodium}/src/libsodium/include/sodium/private/softaes.h
    ${sodium}/src/libsodium/include/sodium/private/sse2_64_32.h
    ${sodium}/src/libsodium/include/sodium/randombytes.h
    ${sodium}/src/libsodium/include/sodium/randombytes_internal_random.h
    ${sodium}/src/libsodium/include/sodium/randombytes_sysrandom.h
    ${sodium}/src/libsodium/include/sodium/runtime.h
    ${sodium}/src/libsodium/include/sodium/utils.h
  PUBLIC
    ${sodium}/src/libsodium/include/sodium/version.h
  PRIVATE
    ${sodium}/src/libsodium/crypto_aead/aegis128l/aead_aegis128l.c
    ${sodium}/src/libsodium/crypto_aead/aegis128l/aegis128l_aesni.c
    ${sodium}/src/libsodium/crypto_aead/aegis128l/aegis128l_armcrypto.c
    ${sodium}/src/libsodium/crypto_aead/aegis128l/aegis128l_soft.c
    ${sodium}/src/libsodium/crypto_aead/aegis256/aead_aegis256.c
    ${sodium}/src/libsodium/crypto_aead/aegis256/aegis256_aesni.c
    ${sodium}/src/libsodium/crypto_aead/aegis256/aegis256_armcrypto.c
    ${sodium}/src/libsodium/crypto_aead/aegis256/aegis256_soft.c
    ${sodium}/src/libsodium/crypto_aead/aes256gcm/aead_aes256gcm.c
    ${sodium}/src/libsodium/crypto_aead/aes256gcm/aesni/aead_aes256gcm_aesni.c
    ${sodium}/src/libsodium/crypto_aead/aes256gcm/armcrypto/aead_aes256gcm_armcrypto.c
    ${sodium}/src/libsodium/crypto_aead/chacha20poly1305/aead_chacha20poly1305.c
    ${sodium}/src/libsodium/crypto_aead/xchacha20poly1305/aead_xchacha20poly1305.c
    ${sodium}/src/libsodium/crypto_auth/crypto_auth.c
    ${sodium}/src/libsodium/crypto_auth/hmacsha256/auth_hmacsha256.c
    ${sodium}/src/libsodium/crypto_auth/hmacsha512/auth_hmacsha512.c
    ${sodium}/src/libsodium/crypto_auth/hmacsha512256/auth_hmacsha512256.c
    ${sodium}/src/libsodium/crypto_box/crypto_box.c
    ${sodium}/src/libsodium/crypto_box/crypto_box_easy.c
    ${sodium}/src/libsodium/crypto_box/crypto_box_seal.c
    ${sodium}/src/libsodium/crypto_box/curve25519xchacha20poly1305/box_curve25519xchacha20poly1305.c
    ${sodium}/src/libsodium/crypto_box/curve25519xchacha20poly1305/box_seal_curve25519xchacha20poly1305.c
    ${sodium}/src/libsodium/crypto_box/curve25519xsalsa20poly1305/box_curve25519xsalsa20poly1305.c
    ${sodium}/src/libsodium/crypto_core/ed25519/core_ed25519.c
    ${sodium}/src/libsodium/crypto_core/ed25519/core_ristretto255.c
    ${sodium}/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c
    ${sodium}/src/libsodium/crypto_core/hchacha20/core_hchacha20.c
    ${sodium}/src/libsodium/crypto_core/hsalsa20/core_hsalsa20.c
    ${sodium}/src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c
    ${sodium}/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c
    ${sodium}/src/libsodium/crypto_core/softaes/softaes.c
    ${sodium}/src/libsodium/crypto_generichash/blake2b/generichash_blake2.c
    ${sodium}/src/libsodium/crypto_generichash/blake2b/ref/blake2b-compress-avx2.c
    ${sodium}/src/libsodium/crypto_generichash/blake2b/ref/blake2b-compress-ref.c
    ${sodium}/src/libsodium/crypto_generichash/blake2b/ref/blake2b-compress-sse41.c
    ${sodium}/src/libsodium/crypto_generichash/blake2b/ref/blake2b-compress-ssse3.c
    ${sodium}/src/libsodium/crypto_generichash/blake2b/ref/blake2b-ref.c
    ${sodium}/src/libsodium/crypto_generichash/blake2b/ref/generichash_blake2b.c
    ${sodium}/src/libsodium/crypto_generichash/crypto_generichash.c
    ${sodium}/src/libsodium/crypto_hash/crypto_hash.c
    ${sodium}/src/libsodium/crypto_hash/sha256/cp/hash_sha256_cp.c
    ${sodium}/src/libsodium/crypto_hash/sha256/hash_sha256.c
    ${sodium}/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c
    ${sodium}/src/libsodium/crypto_hash/sha512/hash_sha512.c
    ${sodium}/src/libsodium/crypto_kdf/blake2b/kdf_blake2b.c
    ${sodium}/src/libsodium/crypto_kdf/crypto_kdf.c
    ${sodium}/src/libsodium/crypto_kdf/hkdf/kdf_hkdf_sha256.c
    ${sodium}/src/libsodium/crypto_kdf/hkdf/kdf_hkdf_sha512.c
    ${sodium}/src/libsodium/crypto_kx/crypto_kx.c
    ${sodium}/src/libsodium/crypto_onetimeauth/crypto_onetimeauth.c
    ${sodium}/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.c
    ${sodium}/src/libsodium/crypto_onetimeauth/poly1305/onetimeauth_poly1305.c
    ${sodium}/src/libsodium/crypto_onetimeauth/poly1305/sse2/poly1305_sse2.c
    ${sodium}/src/libsodium/crypto_pwhash/argon2/argon2-core.c
    ${sodium}/src/libsodium/crypto_pwhash/argon2/argon2-encoding.c
    ${sodium}/src/libsodium/crypto_pwhash/argon2/argon2-fill-block-avx2.c
    ${sodium}/src/libsodium/crypto_pwhash/argon2/argon2-fill-block-avx512f.c
    ${sodium}/src/libsodium/crypto_pwhash/argon2/argon2-fill-block-ref.c
    ${sodium}/src/libsodium/crypto_pwhash/argon2/argon2-fill-block-ssse3.c
    ${sodium}/src/libsodium/crypto_pwhash/argon2/argon2.c
    ${sodium}/src/libsodium/crypto_pwhash/argon2/blake2b-long.c
    ${sodium}/src/libsodium/crypto_pwhash/argon2/pwhash_argon2i.c
    ${sodium}/src/libsodium/crypto_pwhash/argon2/pwhash_argon2id.c
    ${sodium}/src/libsodium/crypto_pwhash/crypto_pwhash.c
    ${sodium}/src/libsodium/crypto_pwhash/scryptsalsa208sha256/crypto_scrypt-common.c
    ${sodium}/src/libsodium/crypto_pwhash/scryptsalsa208sha256/nosse/pwhash_scryptsalsa208sha256_nosse.c
    ${sodium}/src/libsodium/crypto_pwhash/scryptsalsa208sha256/pbkdf2-sha256.c
    ${sodium}/src/libsodium/crypto_pwhash/scryptsalsa208sha256/pwhash_scryptsalsa208sha256.c
    ${sodium}/src/libsodium/crypto_pwhash/scryptsalsa208sha256/scrypt_platform.c
    ${sodium}/src/libsodium/crypto_pwhash/scryptsalsa208sha256/sse/pwhash_scryptsalsa208sha256_sse.c
    ${sodium}/src/libsodium/crypto_scalarmult/crypto_scalarmult.c
    ${sodium}/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c
    ${sodium}/src/libsodium/crypto_scalarmult/curve25519/sandy2x/curve25519_sandy2x.c
    ${sodium}/src/libsodium/crypto_scalarmult/curve25519/sandy2x/fe51_invert.c
    ${sodium}/src/libsodium/crypto_scalarmult/curve25519/sandy2x/fe_frombytes_sandy2x.c
    ${sodium}/src/libsodium/crypto_scalarmult/curve25519/scalarmult_curve25519.c
    ${sodium}/src/libsodium/crypto_scalarmult/ed25519/ref10/scalarmult_ed25519_ref10.c
    ${sodium}/src/libsodium/crypto_scalarmult/ristretto255/ref10/scalarmult_ristretto255_ref10.c
    ${sodium}/src/libsodium/crypto_secretbox/crypto_secretbox.c
    ${sodium}/src/libsodium/crypto_secretbox/crypto_secretbox_easy.c
    ${sodium}/src/libsodium/crypto_secretbox/xchacha20poly1305/secretbox_xchacha20poly1305.c
    ${sodium}/src/libsodium/crypto_secretbox/xsalsa20poly1305/secretbox_xsalsa20poly1305.c
    ${sodium}/src/libsodium/crypto_secretstream/xchacha20poly1305/secretstream_xchacha20poly1305.c
    ${sodium}/src/libsodium/crypto_shorthash/crypto_shorthash.c
    ${sodium}/src/libsodium/crypto_shorthash/siphash24/ref/shorthash_siphash24_ref.c
    ${sodium}/src/libsodium/crypto_shorthash/siphash24/ref/shorthash_siphashx24_ref.c
    ${sodium}/src/libsodium/crypto_shorthash/siphash24/shorthash_siphash24.c
    ${sodium}/src/libsodium/crypto_shorthash/siphash24/shorthash_siphashx24.c
    ${sodium}/src/libsodium/crypto_sign/crypto_sign.c
    ${sodium}/src/libsodium/crypto_sign/ed25519/ref10/keypair.c
    ${sodium}/src/libsodium/crypto_sign/ed25519/ref10/obsolete.c
    ${sodium}/src/libsodium/crypto_sign/ed25519/ref10/open.c
    ${sodium}/src/libsodium/crypto_sign/ed25519/ref10/sign.c
    ${sodium}/src/libsodium/crypto_sign/ed25519/sign_ed25519.c
    ${sodium}/src/libsodium/crypto_stream/chacha20/dolbeau/chacha20_dolbeau-avx2.c
    ${sodium}/src/libsodium/crypto_stream/chacha20/dolbeau/chacha20_dolbeau-ssse3.c
    ${sodium}/src/libsodium/crypto_stream/chacha20/ref/chacha20_ref.c
    ${sodium}/src/libsodium/crypto_stream/chacha20/stream_chacha20.c
    ${sodium}/src/libsodium/crypto_stream/crypto_stream.c
    ${sodium}/src/libsodium/crypto_stream/salsa20/ref/salsa20_ref.c
    ${sodium}/src/libsodium/crypto_stream/salsa20/stream_salsa20.c
    ${sodium}/src/libsodium/crypto_stream/salsa20/xmm6/salsa20_xmm6.c
    ${sodium}/src/libsodium/crypto_stream/salsa20/xmm6int/salsa20_xmm6int-avx2.c
    ${sodium}/src/libsodium/crypto_stream/salsa20/xmm6int/salsa20_xmm6int-sse2.c
    ${sodium}/src/libsodium/crypto_stream/salsa2012/ref/stream_salsa2012_ref.c
    ${sodium}/src/libsodium/crypto_stream/salsa2012/stream_salsa2012.c
    ${sodium}/src/libsodium/crypto_stream/salsa208/ref/stream_salsa208_ref.c
    ${sodium}/src/libsodium/crypto_stream/salsa208/stream_salsa208.c
    ${sodium}/src/libsodium/crypto_stream/xchacha20/stream_xchacha20.c
    ${sodium}/src/libsodium/crypto_stream/xsalsa20/stream_xsalsa20.c
    ${sodium}/src/libsodium/crypto_verify/verify.c
    ${sodium}/src/libsodium/randombytes/internal/randombytes_internal_random.c
    ${sodium}/src/libsodium/randombytes/randombytes.c
    ${sodium}/src/libsodium/randombytes/sysrandom/randombytes_sysrandom.c
    ${sodium}/src/libsodium/sodium/codecs.c
    ${sodium}/src/libsodium/sodium/core.c
    ${sodium}/src/libsodium/sodium/runtime.c
    ${sodium}/src/libsodium/sodium/utils.c
    ${sodium}/src/libsodium/sodium/version.c
)

target_include_directories(
  sodium
  INTERFACE
    ${sodium}/src/libsodium/include
  PRIVATE
    ${sodium}/src/libsodium/include/sodium
)

if(NOT target MATCHES "win32")
  target_compile_options(
    sodium
    PRIVATE
      -fvisibility=hidden
      -fno-strict-aliasing
      -fwrapv
      -flax-vector-conversions
  )
endif()

target_compile_definitions(
  sodium
  PUBLIC
    SODIUM_STATIC=1
  PRIVATE
    _GNU_SOURCE=1
    CONFIGURED=1
    DEV_MODE=1
    HAVE_ATOMIC_OPS=1
    HAVE_C11_MEMORY_FENCES=1
    HAVE_CET_H=1
    HAVE_GCC_MEMORY_FENCES=1
    HAVE_INLINE_ASM=1
    HAVE_INTTYPES_H=1
    HAVE_STDINT_H=1
    HAVE_TI_MODE=1
)

if(target MATCHES "darwin|ios")
  target_compile_definitions(
    sodium
    PRIVATE
      ASM_HIDE_SYMBOL=.private_extern
      TLS=_Thread_local
      HAVE_ARC4RANDOM=1
      HAVE_ARC4RANDOM_BUF=1
      HAVE_CATCHABLE_ABRT=1
      HAVE_CATCHABLE_SEGV=1
      HAVE_CLOCK_GETTIME=1
      HAVE_GETPID=1
      HAVE_MADVISE=1
      HAVE_MEMSET_S=1
      HAVE_MLOCK=1
      HAVE_MMAP=1
      HAVE_MPROTECT=1
      HAVE_NANOSLEEP=1
      HAVE_POSIX_MEMALIGN=1
      HAVE_PTHREAD=1
      HAVE_PTHREAD_PRIO_INHERIT=1
      HAVE_RAISE=1
      HAVE_SYSCONF=1
      HAVE_SYS_MMAN_H=1
      HAVE_SYS_PARAM_H=1
      HAVE_WEAK_SYMBOLS=1
  )

  if(NOT target MATCHES "ios")
    target_compile_definitions(
      sodium
      PRIVATE
        HAVE_GETENTROPY=1
        HAVE_SYS_RANDOM_H=1
    )
  endif()
endif()

if(target MATCHES "linux")
  target_compile_definitions(
    sodium
    PRIVATE
      ASM_HIDE_SYMBOL=.hidden
      TLS=_Thread_local
      HAVE_CATCHABLE_ABRT=1
      HAVE_CATCHABLE_SEGV=1
      HAVE_CLOCK_GETTIME=1
      HAVE_GETPID=1
      HAVE_MADVISE=1
      HAVE_MLOCK=1
      HAVE_MMAP=1
      HAVE_MPROTECT=1
      HAVE_NANOSLEEP=1
      HAVE_POSIX_MEMALIGN=1
      HAVE_PTHREAD_PRIO_INHERIT=1
      HAVE_PTHREAD=1
      HAVE_RAISE=1
      HAVE_SYSCONF=1
      HAVE_SYS_AUXV_H=1
      HAVE_SYS_MMAN_H=1
      HAVE_SYS_PARAM_H=1
      HAVE_SYS_RANDOM_H=1
      HAVE_WEAK_SYMBOLS=1
  )
endif()

if(target MATCHES "win32")
  target_compile_definitions(
    sodium
    PRIVATE
      _CRT_SECURE_NO_WARNINGS=1
      HAVE_RAISE=1
  )
endif()

if(target MATCHES "x64")
  target_compile_definitions(
    sodium
    PRIVATE
      HAVE_CPUID=1
      HAVE_RDRAND=1
      HAVE_EMMINTRIN_H=1 # SSE2
      HAVE_PMMINTRIN_H=1 # SSE3
      HAVE_TMMINTRIN_H=1 # SSSE3
      HAVE_SMMINTRIN_H=1 # SSE4.1
      HAVE_WMMINTRIN_H=1 # AES
      HAVE_AVXINTRIN_H=1 # AVX
      HAVE_AVX2INTRIN_H=1 # AVX2
      HAVE_AVX512FINTRIN_H # AVX512F
  )

  if(NOT target MATCHES "win32")
    target_compile_definitions(
      sodium
      PRIVATE
        HAVE_AMD64_ASM=1
        HAVE_AVX_ASM=1
    )

    target_sources(
      sodium
      PRIVATE
        ${sodium}/src/libsodium/crypto_scalarmult/curve25519/sandy2x/fe51_mul.S
        ${sodium}/src/libsodium/crypto_scalarmult/curve25519/sandy2x/fe51_nsquare.S
        ${sodium}/src/libsodium/crypto_scalarmult/curve25519/sandy2x/fe51_pack.S
        ${sodium}/src/libsodium/crypto_scalarmult/curve25519/sandy2x/ladder.S
        ${sodium}/src/libsodium/crypto_scalarmult/curve25519/sandy2x/sandy2x.S
        ${sodium}/src/libsodium/crypto_stream/salsa20/xmm6/salsa20_xmm6-asm.S
        ${sodium}/src/libsodium/crypto_scalarmult/curve25519/sandy2x/consts.S
    )
  endif()
endif()

if(target MATCHES "arm64")
  target_compile_definitions(
    sodium
    PRIVATE
      HAVE_ARMCRYPTO=1
  )
endif()

test_big_endian(is_big_endian)

if(is_big_endian)
  target_compile_definitions(
    sodium
    PRIVATE
      NATIVE_BIG_ENDIAN=1
  )
else()
  target_compile_definitions(
    sodium
    PRIVATE
      NATIVE_LITTLE_ENDIAN=1
  )
endif()

add_bare_module(sodium_native_bare)

target_sources(
  ${sodium_native_bare}
  PRIVATE
    binding.c
    macros.h
    extensions/tweak/tweak.c
    extensions/tweak/tweak.h
    extensions/pbkdf2/pbkdf2.c
    extensions/pbkdf2/pbkdf2.h
)

target_link_libraries(
  ${sodium_native_bare}
  PRIVATE
    $<TARGET_OBJECTS:sodium>
  PUBLIC
    sodium
)

add_napi_module(sodium_native_node)

target_sources(
  ${sodium_native_node}
  PRIVATE
    binding.c
    macros.h
    extensions/tweak/tweak.c
    extensions/tweak/tweak.h
    extensions/pbkdf2/pbkdf2.c
    extensions/pbkdf2/pbkdf2.h
)

target_link_libraries(
  ${sodium_native_node}
  PRIVATE
    $<TARGET_OBJECTS:sodium>
  PUBLIC
    sodium
)
