#include <nan.h>
#include "macros.h"

#include "../libsodium/src/libsodium/include/sodium.h"

class CryptoPwhashScryptsalsa208sha256StrVerifyAsync : public Nan::AsyncWorker {
 public:
  CryptoPwhashScryptsalsa208sha256StrVerifyAsync(Nan::Callback *callback, const char * str, const char * const passwd, unsigned long long passwdlen)
    : Nan::AsyncWorker(callback, "sodium-native:crypto_pwhash_scryptsalsa208sha256_str_verify_async"), str(str), passwd(passwd), passwdlen(passwdlen) {}
  ~CryptoPwhashScryptsalsa208sha256StrVerifyAsync() {}

  void Execute () {
    if (crypto_pwhash_scryptsalsa208sha256_str_verify(str, passwd, passwdlen) < 0) {
      SetErrorMessage("crypto_pwhash_scryptsalsa208sha256_str_verify_async failed. Either the password is wrong or the operating system most likely refused to allocate the required memory");
      return;
    }
  }

  void HandleOKCallback () {
    Nan::HandleScope scope;

    v8::Local<v8::Value> argv[] = {
        Nan::Null(),
        Nan::True()
    };

    callback->Call(2, argv, async_resource);
  }

  void HandleErrorCallback () {
    Nan::HandleScope scope;

    v8::Local<v8::Value> argv[] = {
        // Due to the way that crypto_pwhash_scryptsalsa208sha256_str_verify
        // signals error different
        // from a verification mismatch, we will count all errors as mismatch.
        // The other possible error is wrong argument sizes, which is protected
        // by macros in binding.cc
        Nan::Null(),
        Nan::False()
    };

    callback->Call(2, argv, async_resource);
  }

 private:
  const char * str;
  const char * const passwd;
  unsigned long long passwdlen;
};
