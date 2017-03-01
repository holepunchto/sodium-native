#ifndef CRYPTO_STREAM_XOR_WRAP_H
#define CRYPTO_STREAM_XOR_WRAP_H

#include <nan.h>
#include "../deps/libsodium/src/libsodium/include/sodium.h"

using namespace v8;

class CryptoStreamXorWrap : public Nan::ObjectWrap {
public:
  unsigned char *nonce;
  unsigned char *key;
  unsigned char next_block[64];
  int remainder = 0;
  uint64_t block_counter = 0;

  static void Init ();
  static Local<Value> NewInstance (unsigned char *nonce, unsigned char *key);
  CryptoStreamXorWrap ();
  ~CryptoStreamXorWrap ();

private:
  static NAN_METHOD(New);
  static NAN_METHOD(Update);
  static NAN_METHOD(Final);
};

#endif
