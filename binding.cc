#include <node.h>
#include <node_buffer.h>
#include <nan.h>
#include "deps/libsodium/src/libsodium/include/sodium.h"
#include "src/crypto_generichash_wrap.h"

using namespace node;
using namespace v8;

// As per Libsodium install docs
#define SODIUM_STATIC

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define CDATA(buf) (unsigned char *) node::Buffer::Data(buf)
#define CLENGTH(buf) (unsigned long long) node::Buffer::Length(buf)
#define LOCAL_STRING(str) Nan::New<String>(str).ToLocalChecked()
#define LOCAL_FUNCTION(fn) Nan::GetFunction(Nan::New<FunctionTemplate>(fn)).ToLocalChecked()
#define EXPORT_NUMBER(name) Nan::Set(target, LOCAL_STRING(#name), Nan::New<Number>(name));
#define EXPORT_STRING(name) Nan::Set(target, LOCAL_STRING(#name), LOCAL_STRING(name));
#define EXPORT_FUNCTION(name) Nan::Set(target, LOCAL_STRING(#name), LOCAL_FUNCTION(name));

#define CALL_SODIUM(fn) \
  int ret = fn; \
  if (ret) { \
    Nan::ThrowError("Sodium operation failed"); \
    return; \
  }

#define CALL_SODIUM_BOOL(fn) \
  int ret = fn; \
  info.GetReturnValue().Set(ret == 0 ? Nan::True() : Nan::False());

#define ASSERT_BUFFER(name, var) \
  if (!name->IsObject()) { \
    Nan::ThrowError(#var " must be a buffer"); \
    return; \
  } \
  Local<Object> var = name->ToObject();

#define ASSERT_BUFFER_SET_LENGTH(name, var) \
  ASSERT_BUFFER(name, var) \
  unsigned long long var##_length = CLENGTH(var);

#define ASSERT_BUFFER_MIN_LENGTH(name, var, length) \
  ASSERT_BUFFER_SET_LENGTH(name, var) \
  if (var##_length < length) { \
    Nan::ThrowError(#var " must be a buffer of size " STR(length)); \
    return; \
  }

// crypto_sign.c

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
  ASSERT_BUFFER_MIN_LENGTH(info[0], signed_message, crypto_sign_BYTES);
  ASSERT_BUFFER(info[1], message); // TODO: this is not correct! must be bigger than BYTES + something
  ASSERT_BUFFER_MIN_LENGTH(info[2], secret_key, crypto_sign_SECRETKEYBYTES);

  unsigned long long signed_message_length_dummy;  // TODO: what is this used for?

  CALL_SODIUM(crypto_sign(CDATA(signed_message), &signed_message_length_dummy, CDATA(message), CLENGTH(message), CDATA(secret_key)))
}

NAN_METHOD(crypto_sign_open) {
  ASSERT_BUFFER_MIN_LENGTH(info[1], signed_message, crypto_sign_BYTES);
  ASSERT_BUFFER(info[0], message); // TODO: this is not correct! must be bigger than BYTES + something
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
    key_len = CLENGTH(key);
  }

  CALL_SODIUM(crypto_generichash(CDATA(output), CLENGTH(output), CDATA(input), CLENGTH(input), key_data, key_len))
}

NAN_METHOD(crypto_generichash_stream) {
  info.GetReturnValue().Set(CryptoGenericHashWrap::NewInstance());
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

NAN_MODULE_INIT(InitAll) {
  if (sodium_init() == -1) return Nan::ThrowError("sodium_init() failed");

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
  EXPORT_FUNCTION(crypto_generichash_stream)

  // crypto_secretbox

  EXPORT_NUMBER(crypto_secretbox_KEYBYTES)
  EXPORT_NUMBER(crypto_secretbox_NONCEBYTES)
  EXPORT_NUMBER(crypto_secretbox_ZEROBYTES)
  EXPORT_NUMBER(crypto_secretbox_BOXZEROBYTES)
  EXPORT_NUMBER(crypto_secretbox_MACBYTES)
  EXPORT_STRING(crypto_secretbox_PRIMITIVE)

  EXPORT_FUNCTION(crypto_secretbox_detached)
  EXPORT_FUNCTION(crypto_secretbox_easy)
  EXPORT_FUNCTION(crypto_secretbox_open_detached)
  EXPORT_FUNCTION(crypto_secretbox_open_easy)

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
  #undef CALL_SODIUM
  #undef CALL_SODIUM_BOOL
}

NODE_MODULE(sodium, InitAll)
