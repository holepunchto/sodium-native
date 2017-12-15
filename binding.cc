#include <node.h>
#include <node_buffer.h>
#include <nan.h>
#include <sodium.h>
#include "src/crypto_generichash_wrap.h"
#include "src/crypto_onetimeauth_wrap.h"
#include "src/crypto_hash_sha256_wrap.h"
#include "src/crypto_hash_sha512_wrap.h"
#include "src/crypto_stream_xor_wrap.h"
#include "src/crypto_stream_chacha20_xor_wrap.h"
#include "src/crypto_secretstream_xchacha20poly1305_state_wrap.h"
#include "src/crypto_pwhash_async.cc"
#include "src/crypto_pwhash_str_async.cc"
#include "src/crypto_pwhash_str_verify_async.cc"
#include "src/macros.h"

using namespace node;
using namespace v8;

// As per Libsodium install docs
#define SODIUM_STATIC

// memory management

NAN_METHOD(sodium_memzero) {
  ASSERT_BUFFER(info[0], buf)

  sodium_memzero(CDATA(buf), CLENGTH(buf));
}

NAN_METHOD(sodium_mlock) {
  ASSERT_BUFFER(info[0], buf)

  CALL_SODIUM(sodium_mlock(CDATA(buf), CLENGTH(buf)))
}

NAN_METHOD(sodium_munlock) {
  ASSERT_BUFFER(info[0], buf)

  CALL_SODIUM(sodium_munlock(CDATA(buf), CLENGTH(buf)))
}

static void SodiumFreeCallback (char * data, void * hint) {
  sodium_free((void *) data);
}

NAN_GETTER(SodiumMemorySecureAccessor) {
  info.GetReturnValue().Set(Nan::New(true));
}

NAN_METHOD(sodium_malloc) {
  ASSERT_UINT_BOUNDS(info[0], size, 0, node::Buffer::kMaxLength)

  v8::Local<v8::Object> buf = Nan::NewBuffer(
    (char *)sodium_malloc(size),
    size,
    SodiumFreeCallback,
    NULL
  ).ToLocalChecked();

  Nan::SetAccessor(buf, LOCAL_STRING("secure"), SodiumMemorySecureAccessor);

  info.GetReturnValue().Set(buf);
}

NAN_METHOD(sodium_mprotect_noaccess) {
  ASSERT_BUFFER(info[0], buf)

  CALL_SODIUM(sodium_mprotect_noaccess(node::Buffer::Data(buf)))
}

NAN_METHOD(sodium_mprotect_readonly) {
  ASSERT_BUFFER(info[0], buf)

  CALL_SODIUM(sodium_mprotect_readonly(node::Buffer::Data(buf)))
}

NAN_METHOD(sodium_mprotect_readwrite) {
  ASSERT_BUFFER(info[0], buf)

  CALL_SODIUM(sodium_mprotect_readwrite(node::Buffer::Data(buf)))
}

// randombytes

NAN_METHOD(randombytes_buf) {
  ASSERT_BUFFER(info[0], random)

  randombytes_buf(CDATA(random), CLENGTH(random));
}

// helpers

NAN_METHOD(sodium_memcmp) {
  ASSERT_BUFFER(info[0], b1)
  ASSERT_BUFFER(info[1], b2)
  ASSERT_UINT(info[2], length)

  CALL_SODIUM_BOOL(sodium_memcmp(CDATA(b1), CDATA(b2), length))
}

NAN_METHOD(sodium_compare) {
  ASSERT_BUFFER(info[0], b1)
  ASSERT_BUFFER(info[1], b2)
  ASSERT_UINT(info[2], length)

  info.GetReturnValue().Set(Nan::New<Number>(sodium_compare(CDATA(b1), CDATA(b2), length)));
}

NAN_METHOD(sodium_pad) {
  ASSERT_BUFFER_SET_LENGTH(info[0], buf)
  ASSERT_UINT_BOUNDS(info[1], unpadded_buflen, 0, buf_length)
  ASSERT_UINT_BOUNDS(info[2], blocksize, 1, buf_length)

  uint32_t padded_buflen = 0;

  CALL_SODIUM(sodium_pad((size_t*) &padded_buflen, CDATA(buf), (size_t) unpadded_buflen, (size_t) blocksize, (size_t) buf_length))

  info.GetReturnValue().Set(Nan::New(padded_buflen));
}

NAN_METHOD(sodium_unpad) {
  ASSERT_BUFFER_SET_LENGTH(info[0], buf)
  ASSERT_UINT_BOUNDS(info[1], padded_buflen, 0, buf_length)
  ASSERT_UINT_BOUNDS(info[2], blocksize, 1, buf_length)

  uint32_t unpadded_buflen = 0;

  CALL_SODIUM(sodium_unpad((size_t*) &unpadded_buflen, CDATA(buf), (size_t) padded_buflen, (size_t) blocksize))

  info.GetReturnValue().Set(Nan::New(unpadded_buflen));
}

// crypto_kx

NAN_METHOD(crypto_kx_keypair) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], public_key, crypto_kx_PUBLICKEYBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[1], secret_key, crypto_kx_SECRETKEYBYTES)

  CALL_SODIUM(crypto_kx_keypair(CDATA(public_key), CDATA(secret_key)))
}

NAN_METHOD(crypto_kx_seed_keypair) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], public_key, crypto_kx_PUBLICKEYBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[1], secret_key, crypto_kx_SECRETKEYBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[2], seed, crypto_kx_SEEDBYTES)

  CALL_SODIUM(crypto_kx_seed_keypair(CDATA(public_key), CDATA(secret_key), CDATA(seed)))
}

NAN_METHOD(crypto_kx_client_session_keys) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], rx, crypto_kx_SESSIONKEYBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[1], tx, crypto_kx_SESSIONKEYBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[2], client_pk, crypto_kx_PUBLICKEYBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[3], client_sk, crypto_kx_SECRETKEYBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[4], server_pk, crypto_kx_PUBLICKEYBYTES)

  CALL_SODIUM(crypto_kx_client_session_keys(CDATA(rx), CDATA(tx), CDATA(client_pk), CDATA(client_sk), CDATA(server_pk)))
}

NAN_METHOD(crypto_kx_server_session_keys) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], rx, crypto_kx_SESSIONKEYBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[1], tx, crypto_kx_SESSIONKEYBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[2], server_pk, crypto_kx_PUBLICKEYBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[3], server_sk, crypto_kx_SECRETKEYBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[4], client_pk, crypto_kx_PUBLICKEYBYTES)

  CALL_SODIUM(crypto_kx_server_session_keys(CDATA(rx), CDATA(tx), CDATA(server_pk), CDATA(server_sk), CDATA(client_pk)))
}

// crypto_sign

NAN_METHOD(crypto_sign_seed_keypair) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], public_key, crypto_sign_PUBLICKEYBYTES);
  ASSERT_BUFFER_MIN_LENGTH(info[1], secret_key, crypto_sign_SECRETKEYBYTES);
  ASSERT_BUFFER_MIN_LENGTH(info[2], seed, crypto_sign_SEEDBYTES);

  CALL_SODIUM(crypto_sign_seed_keypair(CDATA(public_key), CDATA(secret_key), CDATA(seed)))
}

NAN_METHOD(crypto_sign_keypair) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], public_key, crypto_sign_PUBLICKEYBYTES);
  ASSERT_BUFFER_MIN_LENGTH(info[1], secret_key, crypto_sign_SECRETKEYBYTES);

  CALL_SODIUM(crypto_sign_keypair(CDATA(public_key), CDATA(secret_key)))
}

NAN_METHOD(crypto_sign) {
  ASSERT_BUFFER_SET_LENGTH(info[1], message);
  ASSERT_BUFFER_MIN_LENGTH(info[0], signed_message, message_length + crypto_sign_BYTES);
  ASSERT_BUFFER_MIN_LENGTH(info[2], secret_key, crypto_sign_SECRETKEYBYTES);

  unsigned long long signed_message_length_dummy;  // TODO: what is this used for?

  CALL_SODIUM(crypto_sign(CDATA(signed_message), &signed_message_length_dummy, CDATA(message), CLENGTH(message), CDATA(secret_key)))
}

NAN_METHOD(crypto_sign_open) {
  ASSERT_BUFFER_MIN_LENGTH(info[1], signed_message, crypto_sign_BYTES);
  ASSERT_BUFFER_MIN_LENGTH(info[0], message, signed_message_length - crypto_sign_BYTES);
  ASSERT_BUFFER_MIN_LENGTH(info[2], public_key, crypto_sign_PUBLICKEYBYTES);

  unsigned long long message_length_dummy;  // TODO: what is this used for?

  CALL_SODIUM_BOOL(crypto_sign_open(CDATA(message), &message_length_dummy, CDATA(signed_message), signed_message_length, CDATA(public_key)))
}

NAN_METHOD(crypto_sign_detached) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], signature, crypto_sign_BYTES);
  ASSERT_BUFFER(info[1], message);
  ASSERT_BUFFER_MIN_LENGTH(info[2], secret_key, crypto_sign_SECRETKEYBYTES);

  unsigned long long signature_length_dummy; // TODO: what is this used for?

  CALL_SODIUM(crypto_sign_detached(CDATA(signature), &signature_length_dummy, CDATA(message), CLENGTH(message), CDATA(secret_key)))
}

NAN_METHOD(crypto_sign_ed25519_pk_to_curve25519) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], curve25519_pk, crypto_box_PUBLICKEYBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[1], ed25519_pk, crypto_sign_PUBLICKEYBYTES)
  CALL_SODIUM(crypto_sign_ed25519_pk_to_curve25519(CDATA(curve25519_pk), CDATA(ed25519_pk)))
}

NAN_METHOD(crypto_sign_ed25519_sk_to_curve25519) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], curve25519_sk, crypto_box_SECRETKEYBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[1], ed25519_sk, crypto_sign_SECRETKEYBYTES)
  CALL_SODIUM(crypto_sign_ed25519_sk_to_curve25519(CDATA(curve25519_sk), CDATA(ed25519_sk)))
}

NAN_METHOD(crypto_sign_verify_detached) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], signature, crypto_sign_BYTES)
  ASSERT_BUFFER(info[1], message)
  ASSERT_BUFFER_MIN_LENGTH(info[2], public_key, crypto_sign_PUBLICKEYBYTES)

  CALL_SODIUM_BOOL(crypto_sign_verify_detached(CDATA(signature), CDATA(message), CLENGTH(message), CDATA(public_key)))
}

// crypto_generic_hash

NAN_METHOD(crypto_generichash) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], output, crypto_generichash_BYTES_MIN)
  ASSERT_BUFFER(info[1], input)

  unsigned char *key_data = NULL;
  size_t key_len = 0;

  if (info[2]->IsObject()) {
    ASSERT_BUFFER_MIN_LENGTH(info[2], key, crypto_generichash_KEYBYTES_MIN)
    key_data = CDATA(key);
    key_len = key_length;
  }

  CALL_SODIUM(crypto_generichash(CDATA(output), CLENGTH(output), CDATA(input), CLENGTH(input), key_data, key_len))
}

NAN_METHOD(crypto_generichash_batch) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], output, crypto_generichash_BYTES_MIN)

  unsigned char *key_data = NULL;
  size_t key_len = 0;

  if (info[2]->IsObject()) {
    ASSERT_BUFFER_MIN_LENGTH(info[2], key, crypto_generichash_KEYBYTES_MIN)
    key_data = CDATA(key);
    key_len = key_length;
  }

  if (!info[1]->IsArray()) {
    Nan::ThrowError("batch must be an array of buffers");
    return;
  }

  Local<Array> buffers = info[1].As<Array>();

  crypto_generichash_state state;
  crypto_generichash_init(&state, key_data, key_len, output_length);

  uint32_t len = buffers->Length();
  for (uint32_t i = 0; i < len; i++) {
    Local<Value> buf = buffers->Get(i);
    if (!buf->IsObject()) {
      Nan::ThrowError("batch must be an array of buffers");
      return;
    }
    crypto_generichash_update(&state, CDATA(buf), CLENGTH(buf));
  }

  crypto_generichash_final(&state, CDATA(output), output_length);
}

NAN_METHOD(crypto_generichash_instance) {
  unsigned long long output_length = crypto_generichash_BYTES;

  if (info[1]->IsObject()) {
    output_length = CLENGTH(info[1]->ToObject());
  } else if (info[1]->IsNumber()) {
    output_length = info[1]->Uint32Value();
  }

  if (info[0]->IsObject()) {
    ASSERT_BUFFER_MIN_LENGTH(info[0], key, crypto_generichash_KEYBYTES_MIN)
    info.GetReturnValue().Set(CryptoGenericHashWrap::NewInstance(CDATA(key), key_length, output_length));
  } else {
    info.GetReturnValue().Set(CryptoGenericHashWrap::NewInstance(NULL, 0, output_length));
  }
}

// crypto_hash

NAN_METHOD(crypto_hash) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], output, crypto_hash_BYTES)
  ASSERT_BUFFER(info[1], input)

  CALL_SODIUM(crypto_hash(CDATA(output), CDATA(input), CLENGTH(input)))
}

// crypto_box

NAN_METHOD(crypto_box_seed_keypair) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], public_key, crypto_box_PUBLICKEYBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[1], secret_key, crypto_box_SECRETKEYBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[2], seed, crypto_box_SEEDBYTES)

  CALL_SODIUM(crypto_box_seed_keypair(CDATA(public_key), CDATA(secret_key), CDATA(seed)))
}

NAN_METHOD(crypto_box_keypair) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], public_key, crypto_box_PUBLICKEYBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[1], secret_key, crypto_box_SECRETKEYBYTES)

  CALL_SODIUM(crypto_box_keypair(CDATA(public_key), CDATA(secret_key)))
}

NAN_METHOD(crypto_box_detached) {
  ASSERT_BUFFER_SET_LENGTH(info[2], message)
  ASSERT_BUFFER_MIN_LENGTH(info[0], ciphertext, message_length)
  ASSERT_BUFFER_MIN_LENGTH(info[1], mac, crypto_box_MACBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[3], nonce, crypto_box_NONCEBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[4], public_key, crypto_box_PUBLICKEYBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[5], secret_key, crypto_box_SECRETKEYBYTES)

  CALL_SODIUM(crypto_box_detached(
    CDATA(ciphertext), CDATA(mac), CDATA(message), message_length, CDATA(nonce), CDATA(public_key), CDATA(secret_key)
  ))
}

NAN_METHOD(crypto_box_easy) {
  ASSERT_BUFFER_SET_LENGTH(info[1], message)
  ASSERT_BUFFER_MIN_LENGTH(info[0], ciphertext, message_length + crypto_box_MACBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[2], nonce, crypto_box_NONCEBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[3], public_key, crypto_box_PUBLICKEYBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[4], secret_key, crypto_box_SECRETKEYBYTES)

  CALL_SODIUM(crypto_box_easy(CDATA(ciphertext), CDATA(message), message_length, CDATA(nonce), CDATA(public_key), CDATA(secret_key)))
}

NAN_METHOD(crypto_box_open_detached) {
  ASSERT_BUFFER_SET_LENGTH(info[1], ciphertext)
  ASSERT_BUFFER_MIN_LENGTH(info[0], message, ciphertext_length)
  ASSERT_BUFFER_MIN_LENGTH(info[2], mac, crypto_box_MACBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[3], nonce, crypto_box_NONCEBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[4], public_key, crypto_box_PUBLICKEYBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[5], secret_key, crypto_box_SECRETKEYBYTES)

  CALL_SODIUM_BOOL(crypto_box_open_detached(
    CDATA(message), CDATA(ciphertext), CDATA(mac), ciphertext_length, CDATA(nonce), CDATA(public_key), CDATA(secret_key)
  ))
}

NAN_METHOD(crypto_box_open_easy) {
  ASSERT_BUFFER_MIN_LENGTH(info[1], ciphertext, crypto_box_MACBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[0], message, ciphertext_length - crypto_box_MACBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[2], nonce, crypto_box_NONCEBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[3], public_key, crypto_box_PUBLICKEYBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[4], secret_key, crypto_box_SECRETKEYBYTES)

  CALL_SODIUM_BOOL(crypto_box_open_easy(
    CDATA(message), CDATA(ciphertext), ciphertext_length, CDATA(nonce), CDATA(public_key), CDATA(secret_key)
  ))
}

// crypto_box_seal

NAN_METHOD(crypto_box_seal) {
  ASSERT_BUFFER_SET_LENGTH(info[1], message)
  ASSERT_BUFFER_MIN_LENGTH(info[0], ciphertext, message_length + crypto_box_SEALBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[2], public_key, crypto_box_PUBLICKEYBYTES)

  CALL_SODIUM(crypto_box_seal(CDATA(ciphertext), CDATA(message), message_length, CDATA(public_key)))
}

NAN_METHOD(crypto_box_seal_open) {
  ASSERT_BUFFER_SET_LENGTH(info[1], ciphertext)
  ASSERT_BUFFER_MIN_LENGTH(info[0], message, ciphertext_length - crypto_box_SEALBYTES)
  // according to libsodium docs, public key is not required here...
  // see: https://download.libsodium.org/doc/public-key_cryptography/sealed_boxes.html
  ASSERT_BUFFER_MIN_LENGTH(info[2], public_key, crypto_box_PUBLICKEYBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[3], secret_key, crypto_box_SECRETKEYBYTES)

  CALL_SODIUM_BOOL(crypto_box_seal_open(CDATA(message), CDATA(ciphertext), ciphertext_length, CDATA(public_key), CDATA(secret_key)))
}

// crypto_secretbox

NAN_METHOD(crypto_secretbox_detached) {
  ASSERT_BUFFER_SET_LENGTH(info[2], message)
  ASSERT_BUFFER_MIN_LENGTH(info[0], ciphertext, message_length)
  ASSERT_BUFFER_MIN_LENGTH(info[1], mac, crypto_secretbox_MACBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[3], nonce, crypto_secretbox_NONCEBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[4], key, crypto_secretbox_KEYBYTES)

  CALL_SODIUM(crypto_secretbox_detached(CDATA(ciphertext), CDATA(mac), CDATA(message), message_length, CDATA(nonce), CDATA(key)))
}

NAN_METHOD(crypto_secretbox_easy) {
  ASSERT_BUFFER_SET_LENGTH(info[1], message)
  ASSERT_BUFFER_MIN_LENGTH(info[0], ciphertext, crypto_secretbox_MACBYTES + message_length)
  ASSERT_BUFFER_MIN_LENGTH(info[2], nonce, crypto_secretbox_NONCEBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[3], key, crypto_secretbox_KEYBYTES)

  CALL_SODIUM(crypto_secretbox_easy(CDATA(ciphertext), CDATA(message), message_length, CDATA(nonce), CDATA(key)))
}

NAN_METHOD(crypto_secretbox_open_detached) {
  ASSERT_BUFFER_SET_LENGTH(info[1], ciphertext)
  ASSERT_BUFFER_MIN_LENGTH(info[0], message, ciphertext_length)
  ASSERT_BUFFER_MIN_LENGTH(info[2], mac, crypto_secretbox_MACBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[3], nonce, crypto_secretbox_NONCEBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[4], key, crypto_secretbox_KEYBYTES)

  CALL_SODIUM_BOOL(crypto_secretbox_open_detached(CDATA(message), CDATA(ciphertext), CDATA(mac), ciphertext_length, CDATA(nonce), CDATA(key)))
}

NAN_METHOD(crypto_secretbox_open_easy) {
  ASSERT_BUFFER_MIN_LENGTH(info[1], ciphertext, crypto_secretbox_MACBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[0], message, ciphertext_length - crypto_secretbox_MACBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[2], nonce, crypto_secretbox_NONCEBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[3], key, crypto_secretbox_KEYBYTES)

  CALL_SODIUM_BOOL(crypto_secretbox_open_easy(CDATA(message), CDATA(ciphertext), ciphertext_length, CDATA(nonce), CDATA(key)))
}

// crypto_stream

NAN_METHOD(crypto_stream) {
  ASSERT_BUFFER(info[0], ciphertext)
  ASSERT_BUFFER_MIN_LENGTH(info[1], nonce, crypto_stream_NONCEBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[2], key, crypto_stream_KEYBYTES)

  CALL_SODIUM(crypto_stream(CDATA(ciphertext), CLENGTH(ciphertext), CDATA(nonce), CDATA(key)))
}

NAN_METHOD(crypto_stream_xor) {
  ASSERT_BUFFER_SET_LENGTH(info[1], message)
  ASSERT_BUFFER_MIN_LENGTH(info[0], ciphertext, message_length)
  ASSERT_BUFFER_MIN_LENGTH(info[2], nonce, crypto_stream_NONCEBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[3], key, crypto_stream_KEYBYTES)

  CALL_SODIUM(crypto_stream_xor(CDATA(ciphertext), CDATA(message), message_length, CDATA(nonce), CDATA(key)))
}

NAN_METHOD(crypto_stream_xor_instance) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], nonce, crypto_stream_NONCEBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[1], key, crypto_stream_KEYBYTES)

  info.GetReturnValue().Set(CryptoStreamXorWrap::NewInstance(CDATA(nonce), CDATA(key)));
}

NAN_METHOD(crypto_stream_chacha20_xor) {
  ASSERT_BUFFER_SET_LENGTH(info[1], message)
  ASSERT_BUFFER_MIN_LENGTH(info[0], ciphertext, message_length)
  ASSERT_BUFFER_MIN_LENGTH(info[2], nonce, crypto_stream_chacha20_NONCEBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[3], key, crypto_stream_chacha20_KEYBYTES)

  CALL_SODIUM(crypto_stream_chacha20_xor(CDATA(ciphertext), CDATA(message), message_length, CDATA(nonce), CDATA(key)))
}

NAN_METHOD(crypto_stream_chacha20_xor_instance) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], nonce, crypto_stream_chacha20_NONCEBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[1], key, crypto_stream_chacha20_KEYBYTES)

  info.GetReturnValue().Set(CryptoStreamChacha20XorWrap::NewInstance(CDATA(nonce), CDATA(key)));
}
// crypto_auth

NAN_METHOD(crypto_auth) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], output, crypto_auth_BYTES)
  ASSERT_BUFFER(info[1], input)
  ASSERT_BUFFER_MIN_LENGTH(info[2], key, crypto_auth_KEYBYTES)

  CALL_SODIUM(crypto_auth(CDATA(output), CDATA(input), CLENGTH(input), CDATA(key)))
}

NAN_METHOD(crypto_auth_verify) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], hmac, crypto_auth_BYTES)
  ASSERT_BUFFER(info[1], input)
  ASSERT_BUFFER_MIN_LENGTH(info[2], key, crypto_auth_KEYBYTES)

  CALL_SODIUM_BOOL(crypto_auth_verify(CDATA(hmac), CDATA(input), CLENGTH(input), CDATA(key)))
}

// crypto_onetimeauth

NAN_METHOD(crypto_onetimeauth) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], output, crypto_onetimeauth_BYTES)
  ASSERT_BUFFER_SET_LENGTH(info[1], input)
  ASSERT_BUFFER_MIN_LENGTH(info[2], key, crypto_onetimeauth_KEYBYTES)

  CALL_SODIUM(crypto_onetimeauth(CDATA(output), CDATA(input), input_length, CDATA(key)))
}

NAN_METHOD(crypto_onetimeauth_verify) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], output, crypto_onetimeauth_BYTES)
  ASSERT_BUFFER_SET_LENGTH(info[1], input)
  ASSERT_BUFFER_MIN_LENGTH(info[2], key, crypto_onetimeauth_KEYBYTES)

  CALL_SODIUM_BOOL(crypto_onetimeauth_verify(CDATA(output), CDATA(input), input_length, CDATA(key)))
}

NAN_METHOD(crypto_onetimeauth_instance) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], key, crypto_onetimeauth_KEYBYTES)
  info.GetReturnValue().Set(CryptoOnetimeAuthWrap::NewInstance(CDATA(key)));
}

// crypto_pwhash

NAN_METHOD(crypto_pwhash) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], output, crypto_pwhash_BYTES_MIN)
  ASSERT_BUFFER_MIN_LENGTH(info[1], password, crypto_pwhash_PASSWD_MIN)
  ASSERT_BUFFER_MIN_LENGTH(info[2], salt, crypto_pwhash_SALTBYTES)
  ASSERT_UINT_BOUNDS(info[3], opslimit, crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_OPSLIMIT_MAX)
  ASSERT_UINT_BOUNDS(info[4], memlimit, crypto_pwhash_MEMLIMIT_MIN, crypto_pwhash_MEMLIMIT_MAX)
  ASSERT_UINT(info[5], algo)

  CALL_SODIUM(crypto_pwhash(CDATA(output), output_length, (const char *) CDATA(password), password_length, CDATA(salt), opslimit, memlimit, algo))
}

NAN_METHOD(crypto_pwhash_str) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], hash, crypto_pwhash_STRBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[1], password, crypto_pwhash_PASSWD_MIN)
  ASSERT_UINT_BOUNDS(info[2], opslimit, crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_OPSLIMIT_MAX)
  ASSERT_UINT_BOUNDS(info[3], memlimit, crypto_pwhash_MEMLIMIT_MIN, crypto_pwhash_MEMLIMIT_MAX)

  CALL_SODIUM(crypto_pwhash_str((char *) CDATA(hash), (const char *) CDATA(password), password_length, opslimit, memlimit))
}

NAN_METHOD(crypto_pwhash_str_verify) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], hash, crypto_pwhash_STRBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[1], password, crypto_pwhash_PASSWD_MIN)

  CALL_SODIUM_BOOL(crypto_pwhash_str_verify((char *) CDATA(hash), (const char *) CDATA(password), password_length))
}

NAN_METHOD(crypto_pwhash_str_needs_rehash) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], hash, crypto_pwhash_STRBYTES)
  ASSERT_UINT_BOUNDS(info[1], opslimit, crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_OPSLIMIT_MAX)
  ASSERT_UINT_BOUNDS(info[2], memlimit, crypto_pwhash_MEMLIMIT_MIN, crypto_pwhash_MEMLIMIT_MAX)

  int ret = crypto_pwhash_str_needs_rehash((char *) CDATA(hash), opslimit, memlimit);
  info.GetReturnValue().Set(ret == 0 ? Nan::False() : Nan::True());
}

NAN_METHOD(crypto_pwhash_async) {
  ASSERT_BUFFER_SET_LENGTH(info[0], output)
  ASSERT_BUFFER_MIN_LENGTH(info[1], password, crypto_pwhash_PASSWD_MIN)
  ASSERT_BUFFER_MIN_LENGTH(info[2], salt, crypto_pwhash_SALTBYTES)
  ASSERT_UINT_BOUNDS(info[3], opslimit, crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_OPSLIMIT_MAX)
  ASSERT_UINT_BOUNDS(info[4], memlimit, crypto_pwhash_MEMLIMIT_MIN, crypto_pwhash_MEMLIMIT_MAX)
  ASSERT_UINT(info[5], algo)

  ASSERT_FUNCTION(info[6], callback)

  Nan::AsyncQueueWorker(new CryptoPwhashAsync(
    new Nan::Callback(callback),
    CDATA(output),
    output_length,
    (const char *) CDATA(password),
    password_length,
    CDATA(salt),
    opslimit,
    memlimit,
    algo
  ));
}

NAN_METHOD(crypto_pwhash_str_async) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], hash, crypto_pwhash_STRBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[1], password, crypto_pwhash_PASSWD_MIN)
  ASSERT_UINT_BOUNDS(info[2], opslimit, crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_OPSLIMIT_MAX)
  ASSERT_UINT_BOUNDS(info[3], memlimit, crypto_pwhash_MEMLIMIT_MIN, crypto_pwhash_MEMLIMIT_MAX)

  ASSERT_FUNCTION(info[4], callback)

  Nan::AsyncQueueWorker(new CryptoPwhashStrAsync(
    new Nan::Callback(callback),
    (char *) CDATA(hash),
    (const char *) CDATA(password),
    password_length,
    opslimit,
    memlimit
  ));
}

NAN_METHOD(crypto_pwhash_str_verify_async) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], hash, crypto_pwhash_STRBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[1], password, crypto_pwhash_PASSWD_MIN)

  ASSERT_FUNCTION(info[2], callback)

  Nan::AsyncQueueWorker(new CryptoPwhashStrVerifyAsync(
    new Nan::Callback(callback),
    (char *) CDATA(hash),
    (const char *) CDATA(password),
    password_length
  ));
}

// crypto_scalarmult

NAN_METHOD(crypto_scalarmult_base) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], public_key, crypto_scalarmult_BYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[1], secret_key, crypto_scalarmult_SCALARBYTES)

  CALL_SODIUM(crypto_scalarmult_base(CDATA(public_key), CDATA(secret_key)))
}

NAN_METHOD(crypto_scalarmult) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], shared_secret, crypto_scalarmult_BYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[1], secret_key, crypto_scalarmult_SCALARBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[2], public_key, crypto_scalarmult_BYTES)

  CALL_SODIUM(crypto_scalarmult(CDATA(shared_secret), CDATA(secret_key), CDATA(public_key)))
}

// crypto_shorthash

NAN_METHOD(crypto_shorthash) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], output, crypto_shorthash_BYTES)
  ASSERT_BUFFER(info[1], input)
  ASSERT_BUFFER_MIN_LENGTH(info[2], key, crypto_shorthash_KEYBYTES)

  CALL_SODIUM(crypto_shorthash(CDATA(output), CDATA(input), CLENGTH(input), CDATA(key)))
}

// crypto_kdf

NAN_METHOD(crypto_kdf_keygen) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], key, crypto_kdf_KEYBYTES)

  crypto_kdf_keygen(CDATA(key)); // void return value
}

NAN_METHOD(crypto_kdf_derive_from_key) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], subkey, crypto_kdf_BYTES_MIN)
  ASSERT_UINT(info[1], subkey_id)
  ASSERT_BUFFER_MIN_LENGTH(info[2], context, crypto_kdf_CONTEXTBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[3], key, crypto_kdf_KEYBYTES)

  CALL_SODIUM(crypto_kdf_derive_from_key(CDATA(subkey), subkey_length, subkey_id, (const char *) CDATA(context), CDATA(key)))
}

// crypto_hash_sha256

NAN_METHOD(crypto_hash_sha256) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], output, crypto_hash_sha256_BYTES)
  ASSERT_BUFFER(info[1], input)

  CALL_SODIUM(crypto_hash_sha256(CDATA(output), CDATA(input), CLENGTH(input)))
}

NAN_METHOD(crypto_hash_sha256_instance) {
  info.GetReturnValue().Set(CryptoHashSha256Wrap::NewInstance());
}

// crypto_hash_sha512

NAN_METHOD(crypto_hash_sha512) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], output, crypto_hash_sha512_BYTES)
  ASSERT_BUFFER(info[1], input)

  CALL_SODIUM(crypto_hash_sha512(CDATA(output), CDATA(input), CLENGTH(input)))
}

NAN_METHOD(crypto_hash_sha512_instance) {
  info.GetReturnValue().Set(CryptoHashSha512Wrap::NewInstance());
}

// crypto_secretstream

NAN_METHOD(crypto_secretstream_xchacha20poly1305_state_new) {
  info.GetReturnValue().Set(CryptoSecretstreamXchacha20poly1305StateWrap::NewInstance());
}

NAN_METHOD(crypto_secretstream_xchacha20poly1305_keygen) {
  ASSERT_BUFFER_MIN_LENGTH(info[0], key, crypto_secretstream_xchacha20poly1305_KEYBYTES)

  crypto_secretstream_xchacha20poly1305_keygen(CDATA(key));
}

NAN_METHOD(crypto_secretstream_xchacha20poly1305_init_push) {
  ASSERT_UNWRAP(info[0], obj, CryptoSecretstreamXchacha20poly1305StateWrap)
  ASSERT_BUFFER_MIN_LENGTH(info[1], header, crypto_secretstream_xchacha20poly1305_HEADERBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[2], key, crypto_secretstream_xchacha20poly1305_KEYBYTES)

  CALL_SODIUM(crypto_secretstream_xchacha20poly1305_init_pull(&obj->state, CDATA(header), CDATA(key)))
}

NAN_METHOD(crypto_secretstream_xchacha20poly1305_push) {
  ASSERT_UNWRAP(info[0], obj, CryptoSecretstreamXchacha20poly1305StateWrap)
  ASSERT_BUFFER_SET_LENGTH(info[2], message)
  ASSERT_BUFFER_MIN_LENGTH(info[1], ciphertext, crypto_secretstream_xchacha20poly1305_ABYTES + message_length)
  ASSERT_BUFFER_MIN_LENGTH(info[4], tag, crypto_secretstream_xchacha20poly1305_TAGBYTES)

  unsigned char *ad_data = NULL;
  size_t ad_len = 0;

  if (info[3]->IsObject()) {
    ASSERT_BUFFER_SET_LENGTH(info[3], ad)
    ad_data = CDATA(ad);
    ad_len = ad_length;
  }

  unsigned long long mlen;

  CALL_SODIUM(crypto_secretstream_xchacha20poly1305_push(&obj->state, CDATA(ciphertext), &mlen, CDATA(message), message_length, ad_data, ad_len, *CDATA(tag)));

  info.GetReturnValue().Set(Nan::New((uint32_t) mlen));
}

NAN_METHOD(crypto_secretstream_xchacha20poly1305_init_pull) {
  ASSERT_UNWRAP(info[0], obj, CryptoSecretstreamXchacha20poly1305StateWrap)
  ASSERT_BUFFER_MIN_LENGTH(info[1], header, crypto_secretstream_xchacha20poly1305_HEADERBYTES)
  ASSERT_BUFFER_MIN_LENGTH(info[2], key, crypto_secretstream_xchacha20poly1305_KEYBYTES)

  CALL_SODIUM(crypto_secretstream_xchacha20poly1305_init_pull(&obj->state, CDATA(header), CDATA(key)))
}

NAN_METHOD(crypto_secretstream_xchacha20poly1305_pull) {
  ASSERT_UNWRAP(info[0], obj, CryptoSecretstreamXchacha20poly1305StateWrap)
  ASSERT_BUFFER_SET_LENGTH(info[3], ciphertext)
  ASSERT_BUFFER_MIN_LENGTH(info[1], message, ciphertext_length - crypto_secretstream_xchacha20poly1305_ABYTES)

  unsigned char *ad_data = NULL;
  size_t ad_len = 0;

  if (info[4]->IsObject()) {
    ASSERT_BUFFER_SET_LENGTH(info[4], ad)
    ad_data = CDATA(ad);
    ad_len = ad_length;
  }

  unsigned char *tag_p = NULL;
  if (info[2]->IsObject()) {
    ASSERT_BUFFER(info[2], tag)
    tag_p = CDATA(tag);
  }

  unsigned long long clen = 0;

  CALL_SODIUM(crypto_secretstream_xchacha20poly1305_pull(&obj->state, CDATA(message), &clen, tag_p, CDATA(ciphertext), ciphertext_length, ad_data, ad_len));

  info.GetReturnValue().Set(Nan::New((uint32_t) clen));
}

NAN_METHOD(crypto_secretstream_xchacha20poly1305_rekey) {
  ASSERT_UNWRAP(info[0], obj, CryptoSecretstreamXchacha20poly1305StateWrap)

  crypto_secretstream_xchacha20poly1305_rekey(&obj->state);
}

NAN_MODULE_INIT(InitAll) {
  if (sodium_init() == -1) {
    Nan::ThrowError("sodium_init() failed");
    return;
  }

  // memory management
  EXPORT_FUNCTION(sodium_memzero)
  EXPORT_FUNCTION(sodium_mlock)
  EXPORT_FUNCTION(sodium_munlock)
  EXPORT_FUNCTION(sodium_malloc)
  EXPORT_FUNCTION(sodium_mprotect_noaccess)
  EXPORT_FUNCTION(sodium_mprotect_readonly)
  EXPORT_FUNCTION(sodium_mprotect_readwrite)

  // randombytes

  EXPORT_FUNCTION(randombytes_buf)

  // helpers

  EXPORT_FUNCTION(sodium_memcmp)
  EXPORT_FUNCTION(sodium_compare)

  // padding
  EXPORT_FUNCTION(sodium_pad)
  EXPORT_FUNCTION(sodium_unpad)

  // crypto_kx

  EXPORT_NUMBER(crypto_kx_PUBLICKEYBYTES)
  EXPORT_NUMBER(crypto_kx_SECRETKEYBYTES)
  EXPORT_NUMBER(crypto_kx_SEEDBYTES)
  EXPORT_NUMBER(crypto_kx_SESSIONKEYBYTES)
  EXPORT_STRING(crypto_kx_PRIMITIVE)

  EXPORT_FUNCTION(crypto_kx_keypair)
  EXPORT_FUNCTION(crypto_kx_seed_keypair)
  EXPORT_FUNCTION(crypto_kx_client_session_keys)
  EXPORT_FUNCTION(crypto_kx_server_session_keys)

  // crypto_sign

  EXPORT_NUMBER(crypto_sign_SEEDBYTES)
  EXPORT_NUMBER(crypto_sign_PUBLICKEYBYTES)
  EXPORT_NUMBER(crypto_sign_SECRETKEYBYTES)
  EXPORT_NUMBER(crypto_sign_BYTES)

  EXPORT_FUNCTION(crypto_sign_seed_keypair)
  EXPORT_FUNCTION(crypto_sign_keypair)
  EXPORT_FUNCTION(crypto_sign)
  EXPORT_FUNCTION(crypto_sign_open)
  EXPORT_FUNCTION(crypto_sign_detached)
  EXPORT_FUNCTION(crypto_sign_verify_detached)
  EXPORT_FUNCTION(crypto_sign_ed25519_pk_to_curve25519)
  EXPORT_FUNCTION(crypto_sign_ed25519_sk_to_curve25519)

  // crypto_generic_hash

  EXPORT_STRING(crypto_generichash_PRIMITIVE)
  EXPORT_NUMBER(crypto_generichash_BYTES_MIN)
  EXPORT_NUMBER(crypto_generichash_BYTES_MAX)
  EXPORT_NUMBER(crypto_generichash_BYTES)
  EXPORT_NUMBER(crypto_generichash_KEYBYTES_MIN)
  EXPORT_NUMBER(crypto_generichash_KEYBYTES_MAX)
  EXPORT_NUMBER(crypto_generichash_KEYBYTES)

  CryptoGenericHashWrap::Init();

  EXPORT_FUNCTION(crypto_generichash)
  EXPORT_FUNCTION(crypto_generichash_instance)
  EXPORT_FUNCTION(crypto_generichash_batch)

  // crypto_hash

  EXPORT_NUMBER(crypto_hash_BYTES)
  EXPORT_STRING(crypto_hash_PRIMITIVE)
  EXPORT_FUNCTION(crypto_hash)

  // crypto_box

  EXPORT_NUMBER(crypto_box_SEEDBYTES)
  EXPORT_NUMBER(crypto_box_PUBLICKEYBYTES)
  EXPORT_NUMBER(crypto_box_SECRETKEYBYTES)
  EXPORT_NUMBER(crypto_box_NONCEBYTES)
  EXPORT_NUMBER(crypto_box_MACBYTES)
  EXPORT_STRING(crypto_box_PRIMITIVE)

  EXPORT_FUNCTION(crypto_box_seed_keypair)
  EXPORT_FUNCTION(crypto_box_keypair)
  EXPORT_FUNCTION(crypto_box_detached)
  EXPORT_FUNCTION(crypto_box_easy)
  EXPORT_FUNCTION(crypto_box_open_detached)
  EXPORT_FUNCTION(crypto_box_open_easy)

  // crypto_secretbox

  EXPORT_NUMBER(crypto_secretbox_KEYBYTES)
  EXPORT_NUMBER(crypto_secretbox_NONCEBYTES)
  EXPORT_NUMBER(crypto_secretbox_MACBYTES)
  EXPORT_STRING(crypto_secretbox_PRIMITIVE)

  EXPORT_NUMBER(crypto_box_PUBLICKEYBYTES)
  EXPORT_NUMBER(crypto_box_SECRETKEYBYTES)
  EXPORT_NUMBER(crypto_box_SEALBYTES)

  EXPORT_FUNCTION(crypto_box_seal)
  EXPORT_FUNCTION(crypto_box_seal_open)

  EXPORT_FUNCTION(crypto_secretbox_detached)
  EXPORT_FUNCTION(crypto_secretbox_easy)
  EXPORT_FUNCTION(crypto_secretbox_open_detached)
  EXPORT_FUNCTION(crypto_secretbox_open_easy)

  // crypto_stream

  CryptoStreamXorWrap::Init();
  CryptoStreamChacha20XorWrap::Init();

  EXPORT_NUMBER(crypto_stream_KEYBYTES)
  EXPORT_NUMBER(crypto_stream_NONCEBYTES)
  EXPORT_STRING(crypto_stream_PRIMITIVE)

  EXPORT_NUMBER(crypto_stream_chacha20_KEYBYTES)
  EXPORT_NUMBER(crypto_stream_chacha20_NONCEBYTES)


  EXPORT_FUNCTION(crypto_stream)
  EXPORT_FUNCTION(crypto_stream_xor)
  EXPORT_FUNCTION(crypto_stream_xor_instance)

  EXPORT_FUNCTION(crypto_stream_chacha20_xor)
  EXPORT_FUNCTION(crypto_stream_chacha20_xor_instance)

  // crypto_auth

  EXPORT_NUMBER(crypto_auth_BYTES)
  EXPORT_NUMBER(crypto_auth_KEYBYTES)
  EXPORT_STRING(crypto_auth_PRIMITIVE)

  EXPORT_FUNCTION(crypto_auth)
  EXPORT_FUNCTION(crypto_auth_verify)

  // crypto_onetimeauth

  EXPORT_NUMBER(crypto_onetimeauth_BYTES)
  EXPORT_NUMBER(crypto_onetimeauth_KEYBYTES)
  EXPORT_STRING(crypto_onetimeauth_PRIMITIVE)

  CryptoOnetimeAuthWrap::Init();

  EXPORT_FUNCTION(crypto_onetimeauth)
  EXPORT_FUNCTION(crypto_onetimeauth_verify)
  EXPORT_FUNCTION(crypto_onetimeauth_instance)

  // crypto_pwhash

  EXPORT_NUMBER(crypto_pwhash_ALG_ARGON2I13)
  EXPORT_NUMBER(crypto_pwhash_ALG_ARGON2ID13)
  EXPORT_NUMBER(crypto_pwhash_ALG_DEFAULT)
  EXPORT_NUMBER(crypto_pwhash_BYTES_MIN)
  EXPORT_NUMBER(crypto_pwhash_BYTES_MAX)
  EXPORT_NUMBER(crypto_pwhash_PASSWD_MIN)
  EXPORT_NUMBER(crypto_pwhash_PASSWD_MAX)
  EXPORT_NUMBER(crypto_pwhash_SALTBYTES)
  EXPORT_NUMBER(crypto_pwhash_STRBYTES)
  EXPORT_STRING(crypto_pwhash_STRPREFIX)
  EXPORT_NUMBER(crypto_pwhash_OPSLIMIT_MIN)
  EXPORT_NUMBER(crypto_pwhash_OPSLIMIT_MAX)
  EXPORT_NUMBER(crypto_pwhash_MEMLIMIT_MIN)
  EXPORT_NUMBER(crypto_pwhash_MEMLIMIT_MAX)
  EXPORT_NUMBER(crypto_pwhash_OPSLIMIT_INTERACTIVE)
  EXPORT_NUMBER(crypto_pwhash_MEMLIMIT_INTERACTIVE)
  EXPORT_NUMBER(crypto_pwhash_OPSLIMIT_MODERATE)
  EXPORT_NUMBER(crypto_pwhash_MEMLIMIT_MODERATE)
  EXPORT_NUMBER(crypto_pwhash_OPSLIMIT_SENSITIVE)
  EXPORT_NUMBER(crypto_pwhash_MEMLIMIT_SENSITIVE)
  EXPORT_STRING(crypto_pwhash_PRIMITIVE)

  EXPORT_FUNCTION(crypto_pwhash)
  EXPORT_FUNCTION(crypto_pwhash_str)
  EXPORT_FUNCTION(crypto_pwhash_str_verify)
  EXPORT_FUNCTION(crypto_pwhash_str_needs_rehash)

  EXPORT_FUNCTION(crypto_pwhash_async)
  EXPORT_FUNCTION(crypto_pwhash_str_async)
  EXPORT_FUNCTION(crypto_pwhash_str_verify_async)

  // crypto_scalarmult

  EXPORT_STRING(crypto_scalarmult_PRIMITIVE)
  EXPORT_NUMBER(crypto_scalarmult_BYTES)
  EXPORT_NUMBER(crypto_scalarmult_SCALARBYTES)

  EXPORT_FUNCTION(crypto_scalarmult_base)
  EXPORT_FUNCTION(crypto_scalarmult)

  // crypto_shorthash

  EXPORT_NUMBER(crypto_shorthash_BYTES)
  EXPORT_NUMBER(crypto_shorthash_KEYBYTES)
  EXPORT_STRING(crypto_shorthash_PRIMITIVE)

  EXPORT_FUNCTION(crypto_shorthash)

  // crypto_kdf

  EXPORT_NUMBER(crypto_kdf_BYTES_MIN)
  EXPORT_NUMBER(crypto_kdf_BYTES_MAX)
  EXPORT_NUMBER(crypto_kdf_CONTEXTBYTES)
  EXPORT_NUMBER(crypto_kdf_KEYBYTES)
  EXPORT_STRING(crypto_kdf_PRIMITIVE)

  EXPORT_FUNCTION(crypto_kdf_keygen)
  EXPORT_FUNCTION(crypto_kdf_derive_from_key)

  // crypto_hash_256

  CryptoHashSha256Wrap::Init();

  EXPORT_NUMBER(crypto_hash_sha256_BYTES)
  EXPORT_FUNCTION(crypto_hash_sha256)
  EXPORT_FUNCTION(crypto_hash_sha256_instance)

  // crypto_hash_512

  CryptoHashSha512Wrap::Init();

  EXPORT_NUMBER(crypto_hash_sha512_BYTES)
  EXPORT_FUNCTION(crypto_hash_sha512)
  EXPORT_FUNCTION(crypto_hash_sha512_instance)

  // crypto_secretstream

  CryptoSecretstreamXchacha20poly1305StateWrap::Init();

  EXPORT_NUMBER(crypto_secretstream_xchacha20poly1305_ABYTES)
  EXPORT_NUMBER(crypto_secretstream_xchacha20poly1305_HEADERBYTES)
  EXPORT_NUMBER(crypto_secretstream_xchacha20poly1305_KEYBYTES)
  EXPORT_NUMBER(crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX)
  // Unofficial constant
  EXPORT_NUMBER(crypto_secretstream_xchacha20poly1305_TAGBYTES)

  EXPORT_BYTE_TAG_AS_BUFFER(crypto_secretstream_xchacha20poly1305_TAG_MESSAGE)
  EXPORT_BYTE_TAG_AS_BUFFER(crypto_secretstream_xchacha20poly1305_TAG_PUSH)
  EXPORT_BYTE_TAG_AS_BUFFER(crypto_secretstream_xchacha20poly1305_TAG_REKEY)
  EXPORT_BYTE_TAG_AS_BUFFER(crypto_secretstream_xchacha20poly1305_TAG_FINAL)

  EXPORT_FUNCTION(crypto_secretstream_xchacha20poly1305_keygen)
  EXPORT_FUNCTION(crypto_secretstream_xchacha20poly1305_state_new)
  EXPORT_FUNCTION(crypto_secretstream_xchacha20poly1305_init_push)
  EXPORT_FUNCTION(crypto_secretstream_xchacha20poly1305_push)
  EXPORT_FUNCTION(crypto_secretstream_xchacha20poly1305_init_pull)
  EXPORT_FUNCTION(crypto_secretstream_xchacha20poly1305_pull)
  EXPORT_FUNCTION(crypto_secretstream_xchacha20poly1305_rekey)
}

NODE_MODULE(sodium, InitAll)

#undef EXPORT_FUNCTION
#undef EXPORT_NUMBER
#undef EXPORT_STRING
#undef LOCAL_FUNCTION
#undef LOCAL_STRING
#undef CDATA
#undef CLENGTH
#undef STR
#undef STR_HELPER
#undef ASSERT_BUFFER
#undef ASSERT_BUFFER_MIN_LENGTH
#undef ASSERT_BUFFER_SET_LENGTH
#undef ASSERT_UINT
#undef ASSERT_UINT_BOUNDS
#undef ASSERT_FUNCTION
#undef ASSERT_UNWRAP
#undef CALL_SODIUM
#undef CALL_SODIUM_BOOL
