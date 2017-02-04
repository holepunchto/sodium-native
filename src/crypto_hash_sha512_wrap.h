#ifndef CRYPTO_HASH_SHA512_WRAP_H
#define CRYPTO_HASH_SHA512_WRAP_H

#include <nan.h>
#include "../deps/libsodium/src/libsodium/include/sodium.h"

using namespace v8;

class CryptoHashSha512Wrap : public Nan::ObjectWrap {
public:
  static void Init ();
  static Local<Value> NewInstance ();
  CryptoHashSha512Wrap ();
  ~CryptoHashSha512Wrap ();

private:
  crypto_hash_sha512_state *state;

  static NAN_METHOD(New);
  static NAN_METHOD(Update);
  static NAN_METHOD(Final);
};

#endif
