#include <node_api.h>
#include <assert.h>
#include "macros.h"
#include <sodium.h>

napi_value sn_randombytes_random (napi_env env, napi_callback_info info) {
  napi_value result;

  assert(napi_create_uint32(env, randombytes_random(), &result) == napi_ok);
  return result;
}

napi_value sn_randombytes_uniform (napi_env env, napi_callback_info info) {
  SN_ARGV(1, randombytes_uniform);
  SN_ARGV_UINT32(upper_bound, 0)

  napi_value result;
  assert(napi_create_uint32(env, randombytes_uniform(upper_bound), &result) == napi_ok);
  return result;
}

uint8_t typedarray_width(napi_typedarray_type type) {
  switch (type) {
    case napi_int8_array: return 1;
    case napi_uint8_array: return 1;
    case napi_uint8_clamped_array: return 1;
    case napi_int16_array: return 2;
    case napi_uint16_array: return 2;
    case napi_int32_array: return 4;
    case napi_uint32_array: return 4;
    case napi_float32_array: return 4;
    case napi_float64_array: return 8;
    case napi_bigint64_array: return 8;
    case napi_biguint64_array: return 8;
    default: return 0;
  }
}

napi_value sn_randombytes_buf (napi_env env, napi_callback_info info) {
  SN_ARGV(1, randombytes_buf)

  SN_ARGV_TYPEDARRAY(buf, 0)

  randombytes_buf(buf_data, buf_size);

  return NULL;
}


napi_value sn_randombytes_buf_deterministic (napi_env env, napi_callback_info info) {
  SN_ARGV(2, randombytes_buf)

  SN_ARGV_TYPEDARRAY(buf, 0)
  SN_ARGV_TYPEDARRAY(seed, 1)
  
  SN_THROWS(seed_size != randombytes_SEEDBYTES, "seed must be 32 bytes")

  randombytes_buf_deterministic(buf_data, buf_size, seed_data);

  return NULL;
}

napi_value sn_sodium_memcmp(napi_env env, napi_callback_info info) {
  SN_ARGV(2, sodium_memcmp);

  SN_ARGV_TYPEDARRAY(b1, 0)
  SN_ARGV_TYPEDARRAY(b2, 1)

  SN_THROWS(b1_size != b2_size, "buffers must be of same length")

  SN_RETURN_BOOLEAN(sodium_memcmp(b1_data, b2_data, b1_size))
}

napi_value sn_sodium_increment(napi_env env, napi_callback_info info) {
  SN_ARGV(1, sodium_increment);
  SN_ARGV_TYPEDARRAY(n, 0)

  sodium_increment(n_data, n_size);

  return NULL;
}

napi_value sn_sodium_add(napi_env env, napi_callback_info info) {
  SN_ARGV(2, sodium_add);

  SN_ARGV_TYPEDARRAY(a, 0)
  SN_ARGV_TYPEDARRAY(b, 1)

  SN_THROWS(a_size != b_size, "buffers must be of same length")
  sodium_add(a_data, b_data, a_size);

  return NULL;
}

napi_value sn_sodium_sub(napi_env env, napi_callback_info info) {
  SN_ARGV(2, sodium_sub);

  SN_ARGV_TYPEDARRAY(a, 0)
  SN_ARGV_TYPEDARRAY(b, 1)

  SN_THROWS(a_size != b_size, "buffers must be of same length")
  sodium_sub(a_data, b_data, a_size);

  return NULL;
}

napi_value sn_sodium_compare(napi_env env, napi_callback_info info) {
  SN_ARGV(2, sodium_compare);

  SN_ARGV_TYPEDARRAY(a, 0)
  SN_ARGV_TYPEDARRAY(b, 1)

  SN_THROWS(a_size != b_size, "buffers must be of same length")
  int cmp = sodium_compare(a_data, b_data, a_size);

  napi_value result;
  napi_create_int32(env, cmp, &result);

  return result;
}

napi_value sn_sodium_is_zero(napi_env env, napi_callback_info info) {
  SN_ARGV(1, sodium_is_zero);

  SN_ARGV_TYPEDARRAY(a, 0)

  sodium_is_zero(a_data, a_size);
  SN_RETURN_BOOLEAN(sodium_is_zero(a_data, a_size))
}

napi_value sn_sodium_pad(napi_env env, napi_callback_info info) {
  SN_ARGV(3, sodium_pad);

  SN_ARGV_TYPEDARRAY(buf, 0)
  SN_ARGV_UINT32(unpadded_buflen, 1)
  SN_ARGV_UINT32(blocksize, 2)

  SN_THROWS(unpadded_buflen > (int) buf_size, "unpadded length cannot exceed buffer length")
  SN_THROWS(blocksize > (int) buf_size, "block size cannot exceed buffer length")

  napi_value result;
  size_t padded_buflen;
  sodium_pad(&padded_buflen, buf_data, unpadded_buflen, blocksize, buf_size);
  assert(napi_create_uint32(env, padded_buflen, &result) == napi_ok);
  return result;
}

napi_value sn_sodium_unpad(napi_env env, napi_callback_info info) {
  SN_ARGV(3, sodium_unpad);

  SN_ARGV_TYPEDARRAY(buf, 0)
  SN_ARGV_UINT32(padded_buflen, 1)
  SN_ARGV_UINT32(blocksize, 2)

  SN_THROWS(padded_buflen > (int) buf_size, "unpadded length cannot exceed buffer length")
  SN_THROWS(blocksize > (int) buf_size, "block size cannot exceed buffer length")

  napi_value result;
  size_t unpadded_buflen;
  sodium_unpad(&unpadded_buflen, buf_data, padded_buflen, blocksize);
  assert(napi_create_uint32(env, unpadded_buflen, &result) == napi_ok);
  return result;
}

napi_value sn_crypto_sign_keypair(napi_env env, napi_callback_info info) {
  SN_ARGV(2, crypto_sign_keypair)

  SN_ARGV_TYPEDARRAY(pk, 0)
  SN_ARGV_TYPEDARRAY(sk, 1)

  SN_THROWS(pk_size != crypto_sign_PUBLICKEYBYTES, "public key must be 32 bytes")
  SN_THROWS(sk_size != crypto_sign_SECRETKEYBYTES, "secret key must be 64 bytes")

  SN_RETURN(crypto_sign_keypair(pk_data, sk_data), "keypair generation failed")
}

napi_value sn_crypto_sign_seed_keypair(napi_env env, napi_callback_info info) {
  SN_ARGV(3, crypto_sign_seed_keypair)

  SN_ARGV_TYPEDARRAY(pk, 0)
  SN_ARGV_TYPEDARRAY(sk, 1)
  SN_ARGV_TYPEDARRAY(seed, 2)

  SN_THROWS(pk_size != crypto_sign_PUBLICKEYBYTES, "public key must be 32 bytes")
  SN_THROWS(sk_size != crypto_sign_SECRETKEYBYTES, "secret key must be 64 bytes")
  SN_THROWS(seed_size != crypto_sign_SEEDBYTES, "seed must be 32 bytes")

  SN_RETURN(crypto_sign_seed_keypair(pk_data, sk_data, seed_data), "keypair generation failed")
}

napi_value sn_crypto_sign(napi_env env, napi_callback_info info) {
  SN_ARGV(3, crypto_sign)

  SN_ARGV_TYPEDARRAY(signed_message, 0)
  SN_ARGV_TYPEDARRAY(message, 1)
  SN_ARGV_TYPEDARRAY(sk, 2)

  SN_THROWS(signed_message_size != crypto_sign_BYTES + message_size, "signed message buffer must be 64 bytes longer than input")
  SN_THROWS(sk_size != crypto_sign_SECRETKEYBYTES, "secret key must be 64 bytes")

  SN_RETURN(crypto_sign(signed_message_data, NULL, message_data, message_size, sk_data), "signature failed")
}

napi_value sn_crypto_sign_open(napi_env env, napi_callback_info info) {
  SN_ARGV(3, crypto_sign_open)

  SN_ARGV_TYPEDARRAY(message, 0)
  SN_ARGV_TYPEDARRAY(signed_message, 1)
  SN_ARGV_TYPEDARRAY(pk, 2)

  SN_THROWS(message_size != signed_message_size - crypto_sign_BYTES, "message buffer must be 64 bytes shorter than input")
  SN_THROWS(signed_message_size < crypto_sign_BYTES, "signed message must be at least 64 bytes")
  SN_THROWS(pk_size != crypto_sign_PUBLICKEYBYTES, "secret key must be 64 bytes")

  SN_RETURN_BOOLEAN(crypto_sign_open(message_data, NULL, signed_message_data, signed_message_size, pk_data))
}

napi_value sn_crypto_sign_detached(napi_env env, napi_callback_info info) {
  SN_ARGV(3, crypto_sign_detached)

  SN_ARGV_TYPEDARRAY(signature, 0)
  SN_ARGV_TYPEDARRAY(message, 1)
  SN_ARGV_TYPEDARRAY(sk, 2)

  SN_THROWS(signature_size != crypto_sign_BYTES, "signed message buffer must be 64 bytes")
  SN_THROWS(sk_size != crypto_sign_SECRETKEYBYTES, "secret key must be 64 bytes")

  SN_RETURN(crypto_sign_detached(signature_data, NULL, message_data, message_size, sk_data), "signature failed")
}

napi_value sn_crypto_sign_verify_detached(napi_env env, napi_callback_info info) {
  SN_ARGV(3, crypto_sign_verify_detached)

  SN_ARGV_TYPEDARRAY(signature, 0)
  SN_ARGV_TYPEDARRAY(message, 1)
  SN_ARGV_TYPEDARRAY(pk, 2)

  SN_THROWS(signature_size != crypto_sign_BYTES, "signed message must be at least 64 bytes")
  SN_THROWS(pk_size != crypto_sign_PUBLICKEYBYTES, "secret key must be 64 bytes")

  SN_RETURN_BOOLEAN(crypto_sign_verify_detached(signature_data, message_data, message_size, pk_data))
}

napi_value sn_crypto_sign_ed25519_sk_to_pk(napi_env env, napi_callback_info info) {
  SN_ARGV(2, crypto_sign_ed25519_sk_to_pk)

  SN_ARGV_TYPEDARRAY(pk, 0)
  SN_ARGV_TYPEDARRAY(sk, 1)

  SN_THROWS(pk_size != crypto_sign_PUBLICKEYBYTES, "public key buffer must be 32 bytes")
  SN_THROWS(sk_size != crypto_sign_SECRETKEYBYTES, "secret key must be 64 bytes")

  SN_RETURN(crypto_sign_ed25519_sk_to_pk(pk_data, sk_data), "public key generation failed")
}


napi_value sn_crypto_generichash(napi_env env, napi_callback_info info) {
  SN_ARGV_OPTS(2, 3, crypto_generichash)

  SN_ARGV_TYPEDARRAY(output, 0)
  SN_ARGV_TYPEDARRAY(input, 1)

  SN_THROWS(output_size < crypto_generichash_BYTES_MIN, "output buffer must be at least 16 bytes")
  SN_THROWS(output_size > crypto_generichash_BYTES_MAX, "output buffer must be at least 64 bytes")

  void *key_data = NULL;
  size_t key_size = 0;

  if (argc == 3) {
    SN_OPT_ARGV_TYPEDARRAY(key, 2)
    SN_THROWS(key_size < crypto_generichash_KEYBYTES_MIN, "key must be at least 16 bytes")
    SN_THROWS(key_size > crypto_generichash_KEYBYTES_MAX, "key must be at least 64 bytes")
  }

  SN_RETURN(crypto_generichash(output_data, output_size, input_data, input_size, key_data, key_size), "hash failed")
}

napi_value sn_crypto_box_keypair(napi_env env, napi_callback_info info) {
  SN_ARGV(2, crypto_box_keypair)

  SN_ARGV_TYPEDARRAY(pk, 0)
  SN_ARGV_TYPEDARRAY(sk, 1)

  SN_THROWS(pk_size != crypto_box_PUBLICKEYBYTES, "public key must be 32 bytes")
  SN_THROWS(sk_size != crypto_box_SECRETKEYBYTES, "secret key must be 32 bytes")

  SN_RETURN(crypto_box_keypair(pk_data, sk_data), "keypair generation failed")
}

napi_value sn_crypto_box_seed_keypair(napi_env env, napi_callback_info info) {
  SN_ARGV(3, crypto_box_seed_keypair)

  SN_ARGV_TYPEDARRAY(pk, 0)
  SN_ARGV_TYPEDARRAY(sk, 1)
  SN_ARGV_TYPEDARRAY(seed, 2)

  SN_THROWS(pk_size != crypto_box_PUBLICKEYBYTES, "public key must be 32 bytes")
  SN_THROWS(sk_size != crypto_box_SECRETKEYBYTES, "secret key must be 32 bytes")
  SN_THROWS(seed_size != crypto_box_SEEDBYTES, "seed must be 32 bytes")

  SN_RETURN(crypto_box_seed_keypair(pk_data, sk_data, seed_data), "keypair generation failed")
}

napi_value sn_crypto_box_easy(napi_env env, napi_callback_info info) {
  SN_ARGV(5, crypto_box_easy)

  SN_ARGV_TYPEDARRAY(ciphertext, 0)
  SN_ARGV_TYPEDARRAY(message, 1)
  SN_ARGV_TYPEDARRAY(nonce, 2)
  SN_ARGV_TYPEDARRAY(pk, 3)
  SN_ARGV_TYPEDARRAY(sk, 4)

  SN_THROWS(ciphertext_size != message_size + crypto_box_MACBYTES, "ciphertext buffer must be 16 bytes longer than input")
  SN_THROWS(nonce_size != crypto_box_NONCEBYTES, "nonce must be 24 bytes")
  SN_THROWS(sk_size != crypto_box_SECRETKEYBYTES, "secret key must be 32 bytes")
  SN_THROWS(pk_size != crypto_box_PUBLICKEYBYTES, "public key must be 32 bytes")

  SN_RETURN(crypto_box_easy(ciphertext_data, message_data, message_size, nonce_data, pk_data, sk_data), "crypto box failed")
}

napi_value sn_crypto_box_open_easy(napi_env env, napi_callback_info info) {
  SN_ARGV(5, crypto_box_open_easy)

  SN_ARGV_TYPEDARRAY(message, 0)
  SN_ARGV_TYPEDARRAY(ciphertext, 1)
  SN_ARGV_TYPEDARRAY(nonce, 2)
  SN_ARGV_TYPEDARRAY(pk, 3)
  SN_ARGV_TYPEDARRAY(sk, 4)

  SN_THROWS(message_size != ciphertext_size - crypto_box_MACBYTES, "message buffer must be 16 bytes shorter than input")
  SN_THROWS(ciphertext_size < crypto_box_MACBYTES, "ciphertext must be at least 16 bytes")
  SN_THROWS(nonce_size != crypto_box_NONCEBYTES, "nonce must be 24 bytes")
  SN_THROWS(sk_size != crypto_box_SECRETKEYBYTES, "secret key must be 32 bytes")
  SN_THROWS(pk_size != crypto_box_PUBLICKEYBYTES, "public key must be 32 bytes")

  SN_RETURN_BOOLEAN(crypto_box_open_easy(message_data, ciphertext_data, ciphertext_size, nonce_data, pk_data, sk_data))
}

napi_value sn_crypto_box_detached(napi_env env, napi_callback_info info) {
  SN_ARGV(6, crypto_box_detached)

  SN_ARGV_TYPEDARRAY(ciphertext, 0)
  SN_ARGV_TYPEDARRAY(mac, 1)
  SN_ARGV_TYPEDARRAY(message, 2)
  SN_ARGV_TYPEDARRAY(nonce, 3)
  SN_ARGV_TYPEDARRAY(pk, 4)
  SN_ARGV_TYPEDARRAY(sk, 5)

  SN_THROWS(ciphertext_size != message_size, "ciphertext buffer must be equal in length to message")
  SN_THROWS(mac_size != crypto_box_MACBYTES, "mac must be 16 bytes")
  SN_THROWS(nonce_size != crypto_box_NONCEBYTES, "nonce must be 24 bytes")
  SN_THROWS(sk_size != crypto_box_SECRETKEYBYTES, "secret key must be 32 bytes")
  SN_THROWS(pk_size != crypto_box_PUBLICKEYBYTES, "public key must be 32 bytes")

  SN_RETURN(crypto_box_detached(ciphertext_data, mac_data, message_data, message_size, nonce_data, pk_data, sk_data), "signature failed")
}

napi_value sn_crypto_box_open_detached(napi_env env, napi_callback_info info) {
  SN_ARGV(6, crypto_box_open_detached)

  SN_ARGV_TYPEDARRAY(message, 0)
  SN_ARGV_TYPEDARRAY(ciphertext, 1)
  SN_ARGV_TYPEDARRAY(mac, 2)
  SN_ARGV_TYPEDARRAY(nonce, 3)
  SN_ARGV_TYPEDARRAY(pk, 4)
  SN_ARGV_TYPEDARRAY(sk, 5)

  SN_THROWS(message_size != ciphertext_size, "message buffer must be equal in length to ciphertext")
  SN_THROWS(mac_size != crypto_box_MACBYTES, "mac must be 16 bytes")
  SN_THROWS(nonce_size != crypto_box_NONCEBYTES, "nonce must be 24 bytes")
  SN_THROWS(sk_size != crypto_box_SECRETKEYBYTES, "secret key must be 32 bytes")
  SN_THROWS(pk_size != crypto_box_PUBLICKEYBYTES, "public key must be 32 bytes")

  SN_RETURN_BOOLEAN(crypto_box_open_detached(message_data, ciphertext_data, mac_data, ciphertext_size, nonce_data, pk_data, sk_data))
}

napi_value sn_crypto_box_seal(napi_env env, napi_callback_info info) {
  SN_ARGV(3, crypto_box_seal)

  SN_ARGV_TYPEDARRAY(ciphertext, 0)
  SN_ARGV_TYPEDARRAY(message, 1)
  SN_ARGV_TYPEDARRAY(pk, 2)

  SN_THROWS(ciphertext_size != message_size + crypto_box_SEALBYTES, "ciphertext buffer must be 48 bytes longer than input")
  SN_THROWS(pk_size != crypto_box_PUBLICKEYBYTES, "public key must be 32 bytes")

  SN_RETURN(crypto_box_seal(ciphertext_data, message_data, message_size, pk_data), "failed to create seal")
}

napi_value sn_crypto_box_seal_open(napi_env env, napi_callback_info info) {
  SN_ARGV(4, crypto_box_seal_open)

  SN_ARGV_TYPEDARRAY(message, 0)
  SN_ARGV_TYPEDARRAY(ciphertext, 1)
  SN_ARGV_TYPEDARRAY(pk, 2)
  SN_ARGV_TYPEDARRAY(sk, 3)

  SN_THROWS(message_size != ciphertext_size - crypto_box_SEALBYTES, "message buffer must be 48 bytes shorter than input")
  SN_THROWS(ciphertext_size < crypto_box_SEALBYTES, "ciphertext must be at least 48 bytes")
  SN_THROWS(sk_size != crypto_box_SECRETKEYBYTES, "secret key must be 32 bytes")
  SN_THROWS(pk_size != crypto_box_PUBLICKEYBYTES, "public key must be 32 bytes")

  SN_RETURN_BOOLEAN(crypto_box_seal_open(message_data, ciphertext_data, ciphertext_size, pk_data, sk_data))
}

napi_value sn_crypto_secretbox_easy(napi_env env, napi_callback_info info) {
  SN_ARGV(4, crypto_secretbox_easy)

  SN_ARGV_TYPEDARRAY(ciphertext, 0)
  SN_ARGV_TYPEDARRAY(message, 1)
  SN_ARGV_TYPEDARRAY(nonce, 2)
  SN_ARGV_TYPEDARRAY(key, 3)

  SN_THROWS(ciphertext_size != message_size + crypto_secretbox_MACBYTES, "ciphertext buffer must be 16 bytes longer than input")
  SN_THROWS(nonce_size != crypto_secretbox_NONCEBYTES, "nonce must be 24 bytes")
  SN_THROWS(key_size != crypto_secretbox_KEYBYTES, "key must be 32 bytes")

  SN_RETURN(crypto_secretbox_easy(ciphertext_data, message_data, message_size, nonce_data, key_data), "crypto secretbox failed")
}

napi_value sn_crypto_secretbox_open_easy(napi_env env, napi_callback_info info) {
  SN_ARGV(4, crypto_secretbox_open_easy)

  SN_ARGV_TYPEDARRAY(message, 0)
  SN_ARGV_TYPEDARRAY(ciphertext, 1)
  SN_ARGV_TYPEDARRAY(nonce, 2)
  SN_ARGV_TYPEDARRAY(key, 3)

  SN_THROWS(message_size != ciphertext_size - crypto_secretbox_MACBYTES, "message buffer must be 16 bytes shorter than input")
  SN_THROWS(ciphertext_size < crypto_secretbox_MACBYTES, "ciphertext must be at least 16 bytes")
  SN_THROWS(nonce_size != crypto_secretbox_NONCEBYTES, "nonce must be 24 bytes")
  SN_THROWS(key_size != crypto_secretbox_KEYBYTES, "key must be 32 bytes")

  SN_RETURN_BOOLEAN(crypto_secretbox_open_easy(message_data, ciphertext_data, ciphertext_size, nonce_data, key_data))
}

napi_value sn_crypto_secretbox_detached(napi_env env, napi_callback_info info) {
  SN_ARGV(5, crypto_secretbox_detached)

  SN_ARGV_TYPEDARRAY(ciphertext, 0)
  SN_ARGV_TYPEDARRAY(mac, 1)
  SN_ARGV_TYPEDARRAY(message, 2)
  SN_ARGV_TYPEDARRAY(nonce, 3)
  SN_ARGV_TYPEDARRAY(key, 4)

  SN_THROWS(ciphertext_size != message_size, "ciphertext buffer must be equal in length to message")
  SN_THROWS(mac_size != crypto_secretbox_MACBYTES, "mac must be 16 bytes")
  SN_THROWS(nonce_size != crypto_secretbox_NONCEBYTES, "nonce must be 24 bytes")
  SN_THROWS(key_size != crypto_secretbox_KEYBYTES, "key must be 32 bytes")

  SN_RETURN(crypto_secretbox_detached(ciphertext_data, mac_data, message_data, message_size, nonce_data, key_data), "failed to open box")
}

napi_value sn_crypto_secretbox_open_detached(napi_env env, napi_callback_info info) {
  SN_ARGV(5, crypto_secretbox_open_detached)

  SN_ARGV_TYPEDARRAY(message, 0)
  SN_ARGV_TYPEDARRAY(ciphertext, 1)
  SN_ARGV_TYPEDARRAY(mac, 2)
  SN_ARGV_TYPEDARRAY(nonce, 3)
  SN_ARGV_TYPEDARRAY(key, 4)

  SN_THROWS(message_size != ciphertext_size, "message buffer must be equal in length to ciphertext")
  SN_THROWS(mac_size != crypto_secretbox_MACBYTES, "mac must be 16 bytes")
  SN_THROWS(nonce_size != crypto_secretbox_NONCEBYTES, "nonce must be 24 bytes")
  SN_THROWS(key_size != crypto_secretbox_KEYBYTES, "key must be 32 bytes")

  SN_RETURN_BOOLEAN(crypto_secretbox_open_detached(message_data, ciphertext_data, mac_data, ciphertext_size, nonce_data, key_data))
}

napi_value create_sodium_native(napi_env env) {
  napi_value exports;
  assert(napi_create_object(env, &exports) == napi_ok);

  SN_EXPORT_FUNCTION(randombytes_buf, sn_randombytes_buf)
  SN_EXPORT_FUNCTION(randombytes_buf_deterministic, sn_randombytes_buf_deterministic)
  SN_EXPORT_FUNCTION(randombytes_uniform, sn_randombytes_uniform)
  SN_EXPORT_FUNCTION(randombytes_random, sn_randombytes_random)
  SN_EXPORT_FUNCTION(sodium_memcmp, sn_sodium_memcmp)
  SN_EXPORT_FUNCTION(sodium_increment, sn_sodium_increment)
  SN_EXPORT_FUNCTION(sodium_add, sn_sodium_add)
  SN_EXPORT_FUNCTION(sodium_sub, sn_sodium_sub)
  SN_EXPORT_FUNCTION(sodium_compare, sn_sodium_compare)
  SN_EXPORT_FUNCTION(sodium_is_zero, sn_sodium_is_zero)
  SN_EXPORT_FUNCTION(sodium_pad, sn_sodium_pad)
  SN_EXPORT_FUNCTION(sodium_unpad, sn_sodium_unpad)
  SN_EXPORT_FUNCTION(crypto_sign_keypair, sn_crypto_sign_keypair)
  SN_EXPORT_FUNCTION(crypto_sign_seed_keypair, sn_crypto_sign_seed_keypair)
  SN_EXPORT_FUNCTION(crypto_sign, sn_crypto_sign)
  SN_EXPORT_FUNCTION(crypto_sign_open, sn_crypto_sign_open)
  SN_EXPORT_FUNCTION(crypto_sign_detached, sn_crypto_sign_detached)
  SN_EXPORT_FUNCTION(crypto_sign_verify_detached, sn_crypto_sign_verify_detached)
  SN_EXPORT_FUNCTION(crypto_sign_ed25519_sk_to_pk, sn_crypto_sign_ed25519_sk_to_pk)
  SN_EXPORT_FUNCTION(crypto_generichash, sn_crypto_generichash)
  SN_EXPORT_FUNCTION(crypto_box_keypair, sn_crypto_box_keypair)
  SN_EXPORT_FUNCTION(crypto_box_seed_keypair, sn_crypto_box_seed_keypair)
  SN_EXPORT_FUNCTION(crypto_box_easy, sn_crypto_box_easy)
  SN_EXPORT_FUNCTION(crypto_box_open_easy, sn_crypto_box_open_easy)
  SN_EXPORT_FUNCTION(crypto_box_detached, sn_crypto_box_detached)
  SN_EXPORT_FUNCTION(crypto_box_open_detached, sn_crypto_box_open_detached)
  SN_EXPORT_FUNCTION(crypto_box_seal, sn_crypto_box_seal)
  SN_EXPORT_FUNCTION(crypto_box_seal_open, sn_crypto_box_seal_open)
  SN_EXPORT_FUNCTION(crypto_secretbox_easy, sn_crypto_secretbox_easy)
  SN_EXPORT_FUNCTION(crypto_secretbox_open_easy, sn_crypto_secretbox_open_easy)
  SN_EXPORT_FUNCTION(crypto_secretbox_detached, sn_crypto_secretbox_detached)
  SN_EXPORT_FUNCTION(crypto_secretbox_open_detached, sn_crypto_secretbox_open_detached)

  return exports;
}

static napi_value Init(napi_env env, napi_value exports) {
  return create_sodium_native(env);
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
