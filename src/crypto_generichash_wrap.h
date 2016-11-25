#ifndef CRYPTO_GENERIC_HASH_WRAP_H
#define CRYPTO_GENERIC_HASH_WRAP_H

#include <nan.h>
#include "../deps/libsodium/src/libsodium/include/sodium.h"

using namespace v8;

class CryptoGenericHashWrap : public Nan::ObjectWrap {
public:
  static void Init ();
  static Local<Value> NewInstance ();
  CryptoGenericHashWrap ();
  ~CryptoGenericHashWrap ();

private:
  crypto_generichash_state *state;

  static NAN_METHOD(New);
  static NAN_METHOD(Update);
  static NAN_METHOD(Final);
};

#endif
