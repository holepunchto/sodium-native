#include <nan.h>
#include "macros.h"

#include "../deps/libsodium/src/libsodium/include/sodium.h"

class CryptoPwhashStrAsync : public Nan::AsyncWorker {
 public:
  CryptoPwhashStrAsync(Nan::Callback *callback, char * out, const char * const passwd, unsigned long long passwdlen, unsigned long long opslimit, size_t memlimit)
    : Nan::AsyncWorker(callback), out(out), passwd(passwd), passwdlen(passwdlen), opslimit(opslimit), memlimit(memlimit) {}
  ~CryptoPwhashStrAsync() {}

  void Execute () {
    if (crypto_pwhash_str(out, passwd, passwdlen, opslimit, memlimit) < 0) {
      SetErrorMessage("crypto_pwhash_str_async could not complete. The operating system most likely refused to allocate the required memory");
    }
  }

  void HandleOKCallback () {
    Nan::HandleScope scope;

    v8::Local<v8::Value> argv[] = {
        Nan::Null()
    };

    callback->Call(1, argv);
  }

  void HandleErrorCallback () {
    Nan::HandleScope scope;

    v8::Local<v8::Value> argv[] = {
        Nan::Error(ErrorMessage())
    };

    callback->Call(1, argv);
  }

 private:
  char * out;
  const char * const passwd;
  unsigned long long passwdlen;
  unsigned long long opslimit;
  size_t memlimit;
};
