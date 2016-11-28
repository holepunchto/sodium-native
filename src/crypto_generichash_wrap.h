#ifndef CRYPTO_GENERIC_HASH_WRAP_H
#define CRYPTO_GENERIC_HASH_WRAP_H

#include <nan.h>
#include "../deps/libsodium/src/libsodium/include/sodium.h"

using namespace v8;

class CryptoGenericHashWrap : public Nan::ObjectWrap {
public:
  static void Init ();
  static Local<Value> NewInstance (unsigned char *key, unsigned long long key_length, unsigned long long output_length);
  CryptoGenericHashWrap ();
  ~CryptoGenericHashWrap ();

private:
  crypto_generichash_state *state;

  static NAN_METHOD(New);
  static NAN_METHOD(Update);
  static NAN_METHOD(Final);
};

#endif
