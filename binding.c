#include <node_api.h>
#include <assert.h>
#include "macros.h"
#include <sodium.h>

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

napi_value sn_sodium_memzero (napi_env env, napi_callback_info info) {
  SN_ARGV(1, sodium_memzero)
  SN_ARGV_TYPEDARRAY(buf, 0)

  sodium_memzero(buf_data, buf_size);

  return NULL;
}

napi_value sn_sodium_mlock (napi_env env, napi_callback_info info) {
  SN_ARGV(1, sodium_mlock)
  SN_ARGV_TYPEDARRAY(buf, 0)

  SN_RETURN(sodium_mlock(buf_data, buf_size), "memory lock failed")
}

napi_value sn_sodium_munlock (napi_env env, napi_callback_info info) {
  SN_ARGV(1, sodium_munlock)
  SN_ARGV_TYPEDARRAY(buf, 0)

  SN_RETURN(sodium_munlock(buf_data, buf_size), "memory unlock failed")
}

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

napi_value sn_crypto_stream(napi_env env, napi_callback_info info) {
  SN_ARGV(3, crypto_stream)

  SN_ARGV_TYPEDARRAY(ciphertext, 0)
  SN_ARGV_TYPEDARRAY(nonce, 1)
  SN_ARGV_TYPEDARRAY(key, 2)

  SN_THROWS(nonce_size != crypto_stream_NONCEBYTES, "nonce must be 24 bytes")
  SN_THROWS(key_size != crypto_stream_KEYBYTES, "key must be 32 bytes")

  SN_RETURN(crypto_stream(ciphertext_data, ciphertext_size, nonce_data, key_data), "stream encryption failed")
}

napi_value sn_crypto_stream_xor(napi_env env, napi_callback_info info) {
  SN_ARGV(4, crypto_stream_xor)

  SN_ARGV_TYPEDARRAY(ciphertext, 0)
  SN_ARGV_TYPEDARRAY(message, 1)
  SN_ARGV_TYPEDARRAY(nonce, 2)
  SN_ARGV_TYPEDARRAY(key, 3)

  SN_THROWS(ciphertext_size != message_size, "message buffer must be equal in length to ciphertext")
  SN_THROWS(nonce_size != crypto_stream_NONCEBYTES, "nonce must be 24 bytes")
  SN_THROWS(key_size != crypto_stream_KEYBYTES, "key must be 32 bytes")

  SN_RETURN(crypto_stream_xor(ciphertext_data, message_data, message_size, nonce_data, key_data), "stream encryption failed")
}

napi_value sn_crypto_stream_chacha20_xor (napi_env env, napi_callback_info info) {
  SN_ARGV(4, crypto_stream_chacha20_xor)

  SN_ARGV_TYPEDARRAY(ciphertext, 0)
  SN_ARGV_TYPEDARRAY(message, 1)
  SN_ARGV_TYPEDARRAY(nonce, 2)
  SN_ARGV_TYPEDARRAY(key, 3)

  SN_THROWS(ciphertext_size != message_size, "message buffer must be equal in length to ciphertext")
  SN_THROWS(nonce_size != crypto_stream_NONCEBYTES, "nonce must be 24 bytes")
  SN_THROWS(key_size != crypto_stream_KEYBYTES, "key must be 32 bytes")

  SN_RETURN(crypto_stream_chacha20_xor(ciphertext_data, message_data, message_size, nonce_data, key_data), "stream encryption failed")
}

napi_value sn_crypto_auth (napi_env env, napi_callback_info info) {
  SN_ARGV(3, crypto_auth)

  SN_ARGV_TYPEDARRAY(output, 0)
  SN_ARGV_TYPEDARRAY(input, 1)
  SN_ARGV_TYPEDARRAY(key, 2)

  SN_THROWS(output_size != crypto_auth_BYTES, "auth tag must be 32 bytes")
  SN_THROWS(key_size != crypto_auth_KEYBYTES, "key must be 32 bytes")

  SN_RETURN(crypto_auth(output_data, input_data, input_size, key_data), "failed to generate authentication tag")
}

napi_value sn_crypto_auth_verify (napi_env env, napi_callback_info info) {
  SN_ARGV(3, crypto_auth_verify)

  SN_ARGV_TYPEDARRAY(tag, 0)
  SN_ARGV_TYPEDARRAY(input, 1)
  SN_ARGV_TYPEDARRAY(key, 2)

  SN_THROWS(tag_size != crypto_auth_BYTES, "auth tag must be 32 bytes")
  SN_THROWS(key_size != crypto_auth_KEYBYTES, "key must be 32 bytes")

  SN_RETURN_BOOLEAN(crypto_auth_verify(tag_data, input_data, input_size, key_data))
}

napi_value sn_crypto_onetimeauth (napi_env env, napi_callback_info info) {
  SN_ARGV(3, crypto_onetimeauth)

  SN_ARGV_TYPEDARRAY(output, 0)
  SN_ARGV_TYPEDARRAY(input, 1)
  SN_ARGV_TYPEDARRAY(key, 2)

  SN_THROWS(output_size != crypto_onetimeauth_BYTES, "auth tag must be 16 bytes")
  SN_THROWS(key_size != crypto_onetimeauth_KEYBYTES, "key must be 32 bytes")

  SN_RETURN(crypto_onetimeauth(output_data, input_data, input_size, key_data), "failed to generate onetime authentication tag")
}

napi_value sn_crypto_onetimeauth_verify (napi_env env, napi_callback_info info) {
  SN_ARGV(3, crypto_onetimeauth_verify)

  SN_ARGV_TYPEDARRAY(tag, 0)
  SN_ARGV_TYPEDARRAY(input, 1)
  SN_ARGV_TYPEDARRAY(key, 2)

  SN_THROWS(tag_size != crypto_onetimeauth_BYTES, "auth tag must be 16 bytes")
  SN_THROWS(key_size != crypto_onetimeauth_KEYBYTES, "key must be 32 bytes")

  SN_RETURN_BOOLEAN(crypto_onetimeauth_verify(tag_data, input_data, input_size, key_data))
}

// CHECK: memlimit can be >32bit
napi_value sn_crypto_pwhash (napi_env env, napi_callback_info info) {
  SN_ARGV(6, crypto_pwhash)

  SN_ARGV_TYPEDARRAY(output, 0)
  SN_ARGV_TYPEDARRAY(password, 1)
  SN_ARGV_TYPEDARRAY(salt, 2)
  SN_ARGV_UINT32(opslimit, 3)
  SN_ARGV_UINT32(memlimit, 4)
  SN_ARGV_UINT32(algorithm, 5)

  SN_THROWS(output_size < crypto_pwhash_BYTES_MIN, "output must be at least 16 bytes")
  SN_THROWS(output_size > crypto_pwhash_BYTES_MAX, "output must be smaller than 2^32 bytes")
  SN_THROWS(salt_size != crypto_pwhash_SALTBYTES, "salt must be 16 bytes")
  SN_THROWS(opslimit < crypto_pwhash_OPSLIMIT_MIN, "opslimit must be at least 1")
  SN_THROWS(opslimit > crypto_pwhash_OPSLIMIT_MAX, "opslimit must be at most 4294967295")
  SN_THROWS(memlimit < crypto_pwhash_MEMLIMIT_MIN, "memlimit must be at least 8 kB")
  SN_THROWS(memlimit > crypto_pwhash_MEMLIMIT_MAX, "memlimit must be at most 4398 GB")
  SN_THROWS(algorithm < 1, "algorithm must be either Argon2i 1.3 or Argon2id 1.3")
  SN_THROWS(algorithm > 2, "algorithm must be either Argon2i 1.3 or Argon2id 1.3")

  SN_RETURN(crypto_pwhash(output_data, output_size, password_data, password_size, salt_data, opslimit, memlimit, algorithm), "password hashing failed, check memory requirements.")
}

napi_value sn_crypto_pwhash_str (napi_env env, napi_callback_info info) {
  SN_ARGV(4, crypto_pwhash_str)

  SN_ARGV_TYPEDARRAY(output, 0)
  SN_ARGV_TYPEDARRAY(pwd, 1)
  SN_ARGV_UINT32(opslimit, 2)
  SN_ARGV_UINT32(memlimit, 3)

  SN_THROWS(output_size != crypto_pwhash_STRBYTES, "output must be 128 bytes")
  SN_THROWS(opslimit < crypto_pwhash_OPSLIMIT_MIN, "opslimit must be at least 1")
  SN_THROWS(opslimit > crypto_pwhash_OPSLIMIT_MAX, "opslimit must be at most 4294967295")
  SN_THROWS(memlimit < crypto_pwhash_MEMLIMIT_MIN, "memlimit must be at least 8 kB")
  SN_THROWS(memlimit > crypto_pwhash_MEMLIMIT_MAX, "memlimit must be at most 4398 GB")

  SN_RETURN(crypto_pwhash_str(output_data, pwd_data, pwd_size, opslimit, memlimit), "password hashing failed, check memory requirements.")
}

napi_value sn_crypto_pwhash_str_verify (napi_env env, napi_callback_info info) {
  SN_ARGV(2, crypto_pwhash_str_verify)

  SN_ARGV_TYPEDARRAY(str, 0)
  SN_ARGV_TYPEDARRAY(pwd, 1)

  SN_THROWS(str_size != crypto_pwhash_STRBYTES, "password hash must be 128 bytes")

  SN_RETURN_BOOLEAN(crypto_pwhash_str_verify(str_data, pwd_data, pwd_size))
}

// CHECK: returns 1, 0, -1
napi_value sn_crypto_pwhash_str_needs_rehash (napi_env env, napi_callback_info info) {
  SN_ARGV(3, crypto_pwhash_str_needs_rehash)

  SN_ARGV_TYPEDARRAY(hash, 0)
  SN_ARGV_UINT32(opslimit, 1)
  SN_ARGV_UINT32(memlimit, 2)

  SN_THROWS(hash_size != crypto_pwhash_STRBYTES, "password hash must be 128 bytes")
  SN_THROWS(opslimit < crypto_pwhash_OPSLIMIT_MIN, "opslimit must be at least 1")
  SN_THROWS(opslimit > crypto_pwhash_OPSLIMIT_MAX, "opslimit must be at most 4294967295")
  SN_THROWS(memlimit < crypto_pwhash_MEMLIMIT_MIN, "memlimit must be at least 8 kB")
  SN_THROWS(memlimit > crypto_pwhash_MEMLIMIT_MAX, "memlimit must be at most 4398 GB")

  SN_RETURN_BOOLEAN(crypto_pwhash_str_needs_rehash(hash_data, opslimit, memlimit))
}

// CHECK: memlimit can be >32bit
napi_value sn_crypto_pwhash_scryptsalsa208sha256 (napi_env env, napi_callback_info info) {
  SN_ARGV(5, crypto_pwhash_scryptsalsa208sha256)

  SN_ARGV_TYPEDARRAY(output, 0)
  SN_ARGV_TYPEDARRAY(password, 1)
  SN_ARGV_TYPEDARRAY(salt, 2)
  SN_ARGV_UINT32(opslimit, 3)
  SN_ARGV_UINT32(memlimit, 4)

  SN_THROWS(output_size < crypto_pwhash_scryptsalsa208sha256_BYTES_MIN, "output must be at least 16 bytes")
  SN_THROWS(output_size > crypto_pwhash_scryptsalsa208sha256_BYTES_MAX, "output must be at most than 137438953440 bytes")
  SN_THROWS(salt_size != crypto_pwhash_scryptsalsa208sha256_SALTBYTES, "salt must be 32 bytes")
  SN_THROWS(opslimit < crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN, "opslimit must be at least 32768")
  SN_THROWS(opslimit > crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX, "opslimit must be at most 4294967295")
  SN_THROWS(memlimit < crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN, "memlimit must be at least 16.7 MB")
  SN_THROWS(memlimit > crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX, "memlimit must be at most 68.7 GB")

  SN_RETURN(crypto_pwhash_scryptsalsa208sha256(output_data, output_size, password_data, password_size, salt_data, opslimit, memlimit), "password hashing failed, check memory requirements.")
}

napi_value sn_crypto_pwhash_scryptsalsa208sha256_str (napi_env env, napi_callback_info info) {
  SN_ARGV(4, crypto_pwhash_scryptsalsa208sha256_str)

  SN_ARGV_TYPEDARRAY(output, 0)
  SN_ARGV_TYPEDARRAY(pwd, 1)
  SN_ARGV_UINT32(opslimit, 2)
  SN_ARGV_UINT32(memlimit, 3)

  SN_THROWS(output_size != crypto_pwhash_scryptsalsa208sha256_STRBYTES, "output must be 102 bytes")
  SN_THROWS(opslimit < crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN, "opslimit must be at least 32768")
  SN_THROWS(opslimit > crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX, "opslimit must be at most 4294967295")
  SN_THROWS(memlimit < crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN, "memlimit must be at least 16.7 MB")
  SN_THROWS(memlimit > crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX, "memlimit must be at most 68.7 GB")

  SN_RETURN(crypto_pwhash_scryptsalsa208sha256_str(output_data, pwd_data, pwd_size, opslimit, memlimit), "password hashing failed, check memory requirements.")
}

napi_value sn_crypto_pwhash_scryptsalsa208sha256_str_verify (napi_env env, napi_callback_info info) {
  SN_ARGV(2, crypto_pwhash_scryptsalsa208sha256_str_verify)

  SN_ARGV_TYPEDARRAY(str, 0)
  SN_ARGV_TYPEDARRAY(pwd, 1)

  SN_THROWS(str_size != crypto_pwhash_scryptsalsa208sha256_STRBYTES, "password hash must be 102 bytes")

  SN_RETURN_BOOLEAN(crypto_pwhash_scryptsalsa208sha256_str_verify(str_data, pwd_data, pwd_size))
}

// CHECK: returns 1, 0, -1
napi_value sn_crypto_pwhash_scryptsalsa208sha256_str_needs_rehash (napi_env env, napi_callback_info info) {
  SN_ARGV(3, crypto_pwhash_scryptsalsa208sha256_str_needs_rehash)

  SN_ARGV_TYPEDARRAY(hash, 0)
  SN_ARGV_UINT32(opslimit, 1)
  SN_ARGV_UINT32(memlimit, 2)

  SN_THROWS(hash_size != crypto_pwhash_scryptsalsa208sha256_STRBYTES, "password hash must be 102 bytes")
  SN_THROWS(opslimit < crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN, "opslimit must be at least 32768")
  SN_THROWS(opslimit > crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX, "opslimit must be at most 4294967295")
  SN_THROWS(memlimit < crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN, "memlimit must be at least 16.7 MB")
  SN_THROWS(memlimit > crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX, "memlimit must be at most 68.7 GB")

  SN_RETURN_BOOLEAN(crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(hash_data, opslimit, memlimit))
}

napi_value sn_crypto_kx_keypair (napi_env env, napi_callback_info info) {
  SN_ARGV(2, crypto_kx_keypair)

  SN_ARGV_TYPEDARRAY(pk, 0)
  SN_ARGV_TYPEDARRAY(sk, 1)

  SN_THROWS(pk_size != crypto_kx_PUBLICKEYBYTES, "public key buffer must be 32 bytes")
  SN_THROWS(sk_size != crypto_kx_SECRETKEYBYTES, "secret key buffer must be 32 bytes")

  SN_RETURN(crypto_kx_keypair(pk_data, sk_data), "failed to generate keypair")
}

napi_value sn_crypto_kx_seed_keypair (napi_env env, napi_callback_info info) {
  SN_ARGV(3, crypto_kx_seed_keypair)

  SN_ARGV_TYPEDARRAY(pk, 0)
  SN_ARGV_TYPEDARRAY(sk, 1)
  SN_ARGV_TYPEDARRAY(seed, 2)

  SN_THROWS(pk_size != crypto_kx_PUBLICKEYBYTES, "public key buffer must be 32 bytes")
  SN_THROWS(sk_size != crypto_kx_SECRETKEYBYTES, "secret key buffer must be 32 bytes")
  SN_THROWS(seed_size != crypto_kx_SEEDBYTES, "seed must be 32 bytes")

  SN_RETURN(crypto_kx_seed_keypair(pk_data, sk_data, seed_data), "failed to derive keypair from seed")
}

napi_value sn_crypto_kx_client_session_keys (napi_env env, napi_callback_info info) {
  SN_ARGV(5, crypto_kx_client_session_keys)

  SN_ARGV_CHECK_NULL(rx, 0)
  SN_ARGV_CHECK_NULL(tx, 1)

  SN_THROWS(rx_is_null && tx_is_null, "at least one session key must be specified")

  SN_ARGV_TYPEDARRAY(client_pk, 2)
  SN_ARGV_TYPEDARRAY(client_sk, 3)
  SN_ARGV_TYPEDARRAY(server_pk, 4)

  SN_THROWS(client_pk_size != crypto_kx_PUBLICKEYBYTES, "client public key must be 32 bytes")
  SN_THROWS(client_sk_size != crypto_kx_SECRETKEYBYTES, "client secret key must be 32 bytes")
  SN_THROWS(server_pk_size != crypto_kx_PUBLICKEYBYTES, "server public key must be 32 bytes")

  if (rx_is_null) {
    SN_ARGV_TYPEDARRAY(tx, 1)
    SN_THROWS(tx_size != crypto_kx_SESSIONKEYBYTES, "trasnmitting key buffer must be 32 bytes")

    SN_RETURN(crypto_kx_client_session_keys(NULL, tx_data, client_pk_data, client_sk_data, server_pk_data), "failed to derive session keys")
  } else if (tx_is_null) {
    SN_ARGV_TYPEDARRAY(rx, 0)
    SN_THROWS(rx_size != crypto_kx_SESSIONKEYBYTES, "receiving key buffer must be 32 bytes")

    SN_RETURN(crypto_kx_client_session_keys(rx_data, NULL, client_pk_data, client_sk_data, server_pk_data), "failed to derive session keys")
  } else {
    SN_ARGV_TYPEDARRAY(rx, 0)
    SN_ARGV_TYPEDARRAY(tx, 1)
    SN_THROWS(tx_size != crypto_kx_SESSIONKEYBYTES, "trasnmitting key buffer must be 32 bytes or null")
    SN_THROWS(rx_size != crypto_kx_SESSIONKEYBYTES, "receiving key buffer must be 32 bytes or null")

    SN_RETURN(crypto_kx_client_session_keys(rx_data, tx_data, client_pk_data, client_sk_data, server_pk_data), "failed to derive session keys")
  }
}

napi_value sn_crypto_kx_server_session_keys (napi_env env, napi_callback_info info) {
  SN_ARGV(5, crypto_kx_server_session_keys)

  SN_ARGV_CHECK_NULL(rx, 0)
  SN_ARGV_CHECK_NULL(tx, 1)

  SN_THROWS(rx_is_null && tx_is_null, "at least one session key must be specified")

  SN_ARGV_TYPEDARRAY(server_pk, 2)
  SN_ARGV_TYPEDARRAY(server_sk, 3)
  SN_ARGV_TYPEDARRAY(client_pk, 4)

  SN_THROWS(server_pk_size != crypto_kx_PUBLICKEYBYTES, "server public key must be 32 bytes")
  SN_THROWS(server_sk_size != crypto_kx_SECRETKEYBYTES, "server secret key must be 32 bytes")
  SN_THROWS(client_pk_size != crypto_kx_PUBLICKEYBYTES, "client public key must be 32 bytes")

  if (rx_is_null) {
    SN_ARGV_TYPEDARRAY(tx, 1)
    SN_THROWS(tx_size != crypto_kx_SESSIONKEYBYTES, "trasnmitting key buffer must be 32 bytes")

    SN_RETURN(crypto_kx_server_session_keys(NULL, tx_data, server_pk_data, server_sk_data, client_pk_data), "failed to dervie session keys")
  } else if (tx_is_null) {
    SN_ARGV_TYPEDARRAY(rx, 0)
    SN_THROWS(rx_size != crypto_kx_SESSIONKEYBYTES, "receiving key buffer must be 32 bytes")

    SN_RETURN(crypto_kx_server_session_keys(rx_data, NULL, server_pk_data, server_sk_data, client_pk_data), "failed to dervie session keys")
  } else {
    SN_ARGV_TYPEDARRAY(rx, 0)
    SN_ARGV_TYPEDARRAY(tx, 1)
    SN_THROWS(tx_size != crypto_kx_SESSIONKEYBYTES, "trasnmitting key buffer must be 32 bytes or null")
    SN_THROWS(rx_size != crypto_kx_SESSIONKEYBYTES, "receiving key buffer must be 32 bytes or null")

    SN_RETURN(crypto_kx_server_session_keys(rx_data, tx_data, server_pk_data, server_sk_data, client_pk_data), "failed to dervie session keys")
  }
}

napi_value sn_crypto_scalarmult_base (napi_env env, napi_callback_info info) {
  SN_ARGV(2, crypto_scalarmult_base)

  SN_ARGV_TYPEDARRAY(pk, 0)
  SN_ARGV_TYPEDARRAY(sk, 1)

  SN_THROWS(pk_size != crypto_scalarmult_BYTES, "public key buffer must be 32 bytes")
  SN_THROWS(sk_size != crypto_scalarmult_SCALARBYTES, "secret key buffer must be 32 bytes")

  SN_RETURN(crypto_scalarmult_base(pk_data, sk_data), "failed to derive public key")
}

napi_value sn_crypto_scalarmult (napi_env env, napi_callback_info info) {
  SN_ARGV(3, crypto_scalarmult)

  SN_ARGV_TYPEDARRAY(secret, 0)
  SN_ARGV_TYPEDARRAY(sk, 1)
  SN_ARGV_TYPEDARRAY(remote_pk, 2)

  SN_THROWS(secret_size != crypto_scalarmult_BYTES, "shared secret buffer must be 32 bytes")
  SN_THROWS(sk_size != crypto_scalarmult_SCALARBYTES, "secret key buffer must be 32 bytes")
  SN_THROWS(remote_pk_size != crypto_scalarmult_BYTES, "public key buffer must be 32 bytes")

  SN_RETURN(crypto_scalarmult(secret_data, sk_data, remote_pk_data), "failed to derive shared secret")
}

napi_value sn_crypto_scalarmult_ed25519_base (napi_env env, napi_callback_info info) {
  SN_ARGV(2, crypto_scalarmult_ed25519_base)

  SN_ARGV_TYPEDARRAY(pk, 0)
  SN_ARGV_TYPEDARRAY(sk, 1)

  SN_THROWS(pk_size != crypto_scalarmult_ed25519_BYTES, "public key buffer must be 32 bytes")
  SN_THROWS(sk_size != crypto_scalarmult_ed25519_SCALARBYTES, "secret key buffer must be 32 bytes")

  SN_RETURN(crypto_scalarmult_ed25519_base(pk_data, sk_data), "failed to derive public key")
}

napi_value sn_crypto_scalarmult_ed25519 (napi_env env, napi_callback_info info) {
  SN_ARGV(3, crypto_scalarmult_ed25519)

  SN_ARGV_TYPEDARRAY(secret, 0)
  SN_ARGV_TYPEDARRAY(sk, 1)
  SN_ARGV_TYPEDARRAY(remote_pk, 2)

  SN_THROWS(secret_size != crypto_scalarmult_ed25519_BYTES, "shared secret buffer must be 32 bytes")
  SN_THROWS(sk_size != crypto_scalarmult_ed25519_SCALARBYTES, "secret key buffer must be 32 bytes")
  SN_THROWS(remote_pk_size != crypto_scalarmult_ed25519_BYTES, "public key buffer must be 32 bytes")

  SN_RETURN(crypto_scalarmult_ed25519(secret_data, sk_data, remote_pk_data), "failed to derive shared secret")
}

napi_value sn_crypto_core_ed25519_is_valid_point (napi_env env, napi_callback_info info) {
  SN_ARGV(1, crypto_core_ed25519_is_valid_point)

  SN_ARGV_TYPEDARRAY(point, 0)

  SN_THROWS(point_size != crypto_core_ed25519_BYTES, "point must be 32 bytes")

  SN_RETURN_BOOLEAN_FROM_1 (crypto_core_ed25519_is_valid_point(point_data))
}

napi_value sn_crypto_core_ed25519_from_uniform (napi_env env, napi_callback_info info) {
  SN_ARGV(2, crypto_core_ed25519_from_uniform)

  SN_ARGV_TYPEDARRAY(p, 0)
  SN_ARGV_TYPEDARRAY(r, 1)

  SN_THROWS(p_size != crypto_core_ed25519_BYTES, "point must be 32 bytes")
  SN_THROWS(r_size != crypto_core_ed25519_BYTES, "point must be 32 bytes")

  SN_RETURN(crypto_core_ed25519_from_uniform(p_data, r_data), "could not generate curve point from input")
}

napi_value sn_crypto_scalarmult_ed25519_base_noclamp (napi_env env, napi_callback_info info) {
  SN_ARGV(2, crypto_scalarmult_ed25519_base_noclamp)

  SN_ARGV_TYPEDARRAY(pk, 0)
  SN_ARGV_TYPEDARRAY(sk, 1)

  SN_THROWS(pk_size != crypto_scalarmult_ed25519_BYTES, "public key buffer must be 32 bytes")
  SN_THROWS(sk_size != crypto_scalarmult_ed25519_SCALARBYTES, "secret key buffer must be 32 bytes")

  SN_RETURN(crypto_scalarmult_ed25519_base_noclamp(pk_data, sk_data), "failed to derive public key")
}

napi_value sn_crypto_scalarmult_ed25519_noclamp (napi_env env, napi_callback_info info) {
  SN_ARGV(3, crypto_scalarmult_ed25519_noclamp)

  SN_ARGV_TYPEDARRAY(secret, 0)
  SN_ARGV_TYPEDARRAY(sk, 1)
  SN_ARGV_TYPEDARRAY(remote_pk, 2)

  SN_THROWS(secret_size != crypto_scalarmult_ed25519_BYTES, "shared secret buffer must be 32 bytes")
  SN_THROWS(sk_size != crypto_scalarmult_ed25519_SCALARBYTES, "secret key buffer must be 32 bytes")
  SN_THROWS(remote_pk_size != crypto_scalarmult_ed25519_BYTES, "public key buffer must be 32 bytes")

  SN_RETURN(crypto_scalarmult_ed25519_noclamp(secret_data, sk_data, remote_pk_data), "failed to derive shared secret")
}

napi_value create_sodium_native(napi_env env) {
  napi_value exports;
  assert(napi_create_object(env, &exports) == napi_ok);

  SN_EXPORT_FUNCTION(sodium_memzero, sn_sodium_memzero)
  SN_EXPORT_FUNCTION(sodium_mlock, sn_sodium_mlock)
  SN_EXPORT_FUNCTION(sodium_munlock, sn_sodium_munlock)
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
  SN_EXPORT_FUNCTION(crypto_stream, sn_crypto_stream)
  SN_EXPORT_FUNCTION(crypto_stream_xor, sn_crypto_stream_xor)
  SN_EXPORT_FUNCTION(crypto_stream_chacha20_xor, sn_crypto_stream_chacha20_xor)
  SN_EXPORT_FUNCTION(crypto_auth, sn_crypto_auth)
  SN_EXPORT_FUNCTION(crypto_auth_verify, sn_crypto_auth_verify)
  SN_EXPORT_FUNCTION(crypto_onetimeauth, sn_crypto_onetimeauth)
  SN_EXPORT_FUNCTION(crypto_onetimeauth_verify, sn_crypto_onetimeauth_verify)
  SN_EXPORT_FUNCTION(crypto_pwhash, sn_crypto_pwhash)
  SN_EXPORT_FUNCTION(crypto_pwhash_str, sn_crypto_pwhash_str)
  SN_EXPORT_FUNCTION(crypto_pwhash_str_verify, sn_crypto_pwhash_str_verify)
  SN_EXPORT_FUNCTION(crypto_pwhash_str_needs_rehash, sn_crypto_pwhash_str_needs_rehash)
  SN_EXPORT_FUNCTION(crypto_pwhash_scryptsalsa208sha256, sn_crypto_pwhash_scryptsalsa208sha256)
  SN_EXPORT_FUNCTION(crypto_pwhash_scryptsalsa208sha256_str, sn_crypto_pwhash_scryptsalsa208sha256_str)
  SN_EXPORT_FUNCTION(crypto_pwhash_scryptsalsa208sha256_str_verify, sn_crypto_pwhash_scryptsalsa208sha256_str_verify)
  SN_EXPORT_FUNCTION(crypto_pwhash_scryptsalsa208sha256_str_needs_rehash, sn_crypto_pwhash_scryptsalsa208sha256_str_needs_rehash)
  SN_EXPORT_FUNCTION(crypto_kx_keypair, sn_crypto_kx_keypair)
  SN_EXPORT_FUNCTION(crypto_kx_seed_keypair, sn_crypto_kx_seed_keypair)
  SN_EXPORT_FUNCTION(crypto_kx_client_session_keys, sn_crypto_kx_client_session_keys)
  SN_EXPORT_FUNCTION(crypto_kx_server_session_keys, sn_crypto_kx_server_session_keys)
  SN_EXPORT_FUNCTION(crypto_scalarmult_base, sn_crypto_scalarmult_base)
  SN_EXPORT_FUNCTION(crypto_scalarmult, sn_crypto_scalarmult)
  SN_EXPORT_FUNCTION(crypto_scalarmult_ed25519_base, sn_crypto_scalarmult_ed25519_base)
  SN_EXPORT_FUNCTION(crypto_scalarmult_ed25519, sn_crypto_scalarmult_ed25519)
  SN_EXPORT_FUNCTION(crypto_scalarmult_ed25519_base_noclamp, sn_crypto_scalarmult_ed25519_base_noclamp)
  SN_EXPORT_FUNCTION(crypto_scalarmult_ed25519_noclamp, sn_crypto_scalarmult_ed25519_noclamp)
  SN_EXPORT_FUNCTION(crypto_core_ed25519_is_valid_point, sn_crypto_core_ed25519_is_valid_point)
  SN_EXPORT_FUNCTION(crypto_core_ed25519_from_uniform, sn_crypto_core_ed25519_from_uniform)

  return exports;
}

static napi_value Init(napi_env env, napi_value exports) {
  return create_sodium_native(env);
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
