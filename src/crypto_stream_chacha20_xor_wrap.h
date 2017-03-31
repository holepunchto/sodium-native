#ifndef CRYPTO_STREAM_CHACHA20_XOR_WRAP_H
#define CRYPTO_STREAM_CHACHA20_XOR_WRAP_H

#include <nan.h>
#include "../deps/libsodium/src/libsodium/include/sodium.h"

using namespace v8;

class CryptoStreamChacha20XorWrap : public Nan::ObjectWrap {
public:
  unsigned char *nonce;
  unsigned char *key;
  unsigned char next_block[64];
  int remainder;
  uint64_t block_counter;

  static void Init ();
  static Local<Value> NewInstance (unsigned char *nonce, unsigned char *key);
  CryptoStreamChacha20XorWrap ();
  ~CryptoStreamChacha20XorWrap ();

private:
  static NAN_METHOD(New);
  static NAN_METHOD(Update);
  static NAN_METHOD(Final);
};

#endif
