#include <nan.h>
#include "macros.h"

#include "../deps/libsodium/src/libsodium/include/sodium.h"

class CryptoPwhashStrVerifyAsync : public Nan::AsyncWorker {
 public:
  CryptoPwhashStrVerifyAsync(Nan::Callback *callback, const char * str, const char * const passwd, unsigned long long passwdlen)
    : Nan::AsyncWorker(callback), str(str), passwd(passwd), passwdlen(passwdlen) {}
  ~CryptoPwhashStrVerifyAsync() {}

  void Execute () {
    if (crypto_pwhash_str_verify(str, passwd, passwdlen) < 0) {
      SetErrorMessage("crypto_pwhash_str_verify_async failed. Either the password is wrong or the operating system most likely refused to allocate the required memory");
      return;
    }
  }

  void HandleOKCallback () {
    Nan::HandleScope scope;

    v8::Local<v8::Value> argv[] = {
        Nan::Null(),
        Nan::True()
    };

    callback->Call(2, argv);
  }

  void HandleErrorCallback () {
    Nan::HandleScope scope;

    v8::Local<v8::Value> argv[] = {
        // Due to an issue with crypto_pwhash_str_verify not counting an malloc
        // error different from a verification mismatch we predict that a mismatch
        // is the most likely cause of the error
        // Nan::Error(ErrorMessage())
        Nan::Null(),
        Nan::False()
    };

    callback->Call(2, argv);
  }

 private:
  const char * str;
  const char * const passwd;
  unsigned long long passwdlen;
};
