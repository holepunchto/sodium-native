#ifndef CRYPTO_ONETIME_AUTH_WRAP_H
#define CRYPTO_ONETIME_AUTH_WRAP_H

#include <nan.h>
#include <sodium.h>

using namespace v8;

class CryptoOnetimeAuthWrap : public Nan::ObjectWrap {
public:
  static void Init ();
  static Local<Value> NewInstance (unsigned char *key);
  CryptoOnetimeAuthWrap ();
  ~CryptoOnetimeAuthWrap ();

private:
  crypto_onetimeauth_state state;

  static NAN_METHOD(New);
  static NAN_METHOD(Update);
  static NAN_METHOD(Final);
};

#endif
