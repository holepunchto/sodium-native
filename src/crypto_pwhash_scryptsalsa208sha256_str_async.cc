#include <nan.h>
#include "macros.h"

#include "../libsodium/src/libsodium/include/sodium.h"

class CryptoPwhashScryptsalsa208sha256StrAsync : public Nan::AsyncWorker {
 public:
  CryptoPwhashScryptsalsa208sha256StrAsync(Nan::Callback *callback, char * out, const char * const passwd, unsigned long long passwdlen, unsigned long long opslimit, size_t memlimit)
    : Nan::AsyncWorker(callback, "sodium-native:crypto_pwhash_scryptsalsa208sha256_str_async"), out(out), passwd(passwd), passwdlen(passwdlen), opslimit(opslimit), memlimit(memlimit) {}
  ~CryptoPwhashScryptsalsa208sha256StrAsync() {}

  void Execute () {
    CALL_SODIUM_ASYNC_WORKER(errorno, crypto_pwhash_scryptsalsa208sha256_str(out, passwd, passwdlen, opslimit, memlimit))
  }

  void HandleOKCallback () {
    Nan::HandleScope scope;

    v8::Local<v8::Value> argv[] = {
        Nan::Null()
    };

    callback->Call(1, argv, async_resource);
  }

  void HandleErrorCallback () {
    Nan::HandleScope scope;

    v8::Local<v8::Value> argv[] = {
        ERRNO_EXCEPTION(errorno)
    };

    callback->Call(1, argv, async_resource);
  }

 private:
  char * out;
  const char * const passwd;
  unsigned long long passwdlen;
  unsigned long long opslimit;
  size_t memlimit;
  int errorno;
};
