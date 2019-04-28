#include <nan.h>
#include "macros.h"

#include "../libsodium/src/libsodium/include/sodium.h"

class CryptoPwhashScryptsalsa208sha256Async : public Nan::AsyncWorker {
 public:
  CryptoPwhashScryptsalsa208sha256Async(Nan::Callback *callback, unsigned char * const out, unsigned long long outlen, const char * const passwd, unsigned long long passwdlen, const unsigned char * const salt, unsigned long long opslimit, size_t memlimit)
    : Nan::AsyncWorker(callback, "sodium-native:crypto_pwhash_scryptsalsa208sha256_async"), out(out), outlen(outlen), passwd(passwd), passwdlen(passwdlen), salt(salt), opslimit(opslimit), memlimit(memlimit) {}
  ~CryptoPwhashScryptsalsa208sha256Async() {}

  void Execute () {
    CALL_SODIUM_ASYNC_WORKER(errorno, crypto_pwhash_scryptsalsa208sha256(out, outlen, passwd, passwdlen, salt, opslimit, memlimit))
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
  unsigned char * const out;
  unsigned long long outlen;
  const char * const passwd;
  unsigned long long passwdlen;
  const unsigned char * const salt;
  unsigned long long opslimit;
  size_t memlimit;
  int errorno;
};
