#include <nan.h>
#include <errno.h>
#include "macros.h"

#include "../libsodium/src/libsodium/include/sodium.h"

class CryptoPwhashStrVerifyAsync : public Nan::AsyncWorker {
 public:
  CryptoPwhashStrVerifyAsync(Nan::Callback *callback, const char * str, const char * const passwd, unsigned long long passwdlen)
    : Nan::AsyncWorker(callback), str(str), passwd(passwd), passwdlen(passwdlen) {}
  ~CryptoPwhashStrVerifyAsync() {}

  void Execute () {
    // HACK need to reset errno since some code paths cause -1, but don't set
    // errno
    errno = 0;
    CALL_SODIUM_ASYNC_WORKER(errorno, crypto_pwhash_str_verify(str, passwd, passwdlen))
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

    // Mirrored in binding.cc near NAN_METHOD(crypto_pwhash_str_verify)
    // EINVAL is set if MISMATCH or if passwordlen is too short, but we check
    // the latter with assertions above
    if (errorno == EINVAL) {
      v8::Local<v8::Value> argv[] = {
          Nan::Null(),
          Nan::False()
      };

      callback->Call(2, argv, async_resource);
      return;
    } else {
      // Too long password or ENOMEM or ...
      v8::Local<v8::Value> argv[] = {
          errorno ? ERRNO_EXCEPTION(errorno) : Nan::Error("Unknown Error. Most likely an invalid formatted str")
      };

      callback->Call(1, argv, async_resource);
    }
  }

 private:
  const char * str;
  const char * const passwd;
  unsigned long long passwdlen;
  int errorno;
};
