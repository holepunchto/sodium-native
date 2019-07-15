#ifndef SODIDUM_NATIVE_MACROS_H
#define SODIDUM_NATIVE_MACROS_H

#include <errno.h>
#include <string.h>

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define CDATA(buf) (unsigned char *) node::Buffer::Data(buf)
#define CLENGTH(buf) (unsigned long long) node::Buffer::Length(buf)
#define LOCAL_STRING(str) Nan::New<v8::String>(str).ToLocalChecked()
#define LOCAL_FUNCTION(fn) Nan::GetFunction(Nan::New<v8::FunctionTemplate>(fn)).ToLocalChecked()
#define EXPORT_NUMBER(name) Nan::Set(target, LOCAL_STRING(#name), Nan::New<v8::Number>(name));
#define EXPORT_NUMBER_VALUE(name, value) Nan::Set(target, LOCAL_STRING(#name), Nan::New<v8::Number>(value));
#define EXPORT_STRING(name) Nan::Set(target, LOCAL_STRING(#name), LOCAL_STRING(name));
#define EXPORT_FUNCTION(name) Nan::Set(target, LOCAL_STRING(#name), LOCAL_FUNCTION(name));
#define EXPORT_BYTE_TAG_AS_BUFFER(name) \
  const char name##_TMP = name; \
  Nan::Set(target, \
           LOCAL_STRING(#name), \
           Nan::CopyBuffer(&name##_TMP, crypto_secretstream_xchacha20poly1305_TAGBYTES).ToLocalChecked());

// workaround for old compilers
#ifndef SIZE_MAX
#define SIZE_MAX ((size_t) - 1)
#endif

// Warning: This is only because we know for now that tags are one byte, and
// it is hard to expose the tag pointer to javascript, other than as a Buffer
#ifndef crypto_secretstream_xchacha20poly1305_TAGBYTES
#define crypto_secretstream_xchacha20poly1305_TAGBYTES 1U
#endif

#define ERRNO_EXCEPTION(errorno) \
  Nan::ErrnoException(errorno, NULL, strerror(errorno))

#define CALL_SODIUM(fn) \
  int ret = fn; \
  if (ret) { \
    Nan::ThrowError(ERRNO_EXCEPTION(errno)); \
    return; \
  }

// SetErrorMessage is only to trigger AsyncWorker's error callback
#define CALL_SODIUM_ASYNC_WORKER(errorno_var, fn) \
  int ret = fn; \
  if (ret) { \
    SetErrorMessage("error"); \
    errorno_var = errno; \
  }

#define CALL_SODIUM_BOOL(fn) \
  int ret = fn; \
  info.GetReturnValue().Set(ret == 0 ? Nan::True() : Nan::False());

#define CALL_SODIUM_BOOL_INV(fn) \
  int ret = fn; \
  info.GetReturnValue().Set(ret == 1 ? Nan::True() : Nan::False());

#define ASSERT_BUFFER(name, var) \
  if (!name->IsObject()) { \
    Nan::ThrowError(#var " must be a buffer"); \
    return; \
  } \
  v8::Local<v8::Object> var = name->ToObject(v8::Isolate::GetCurrent()->GetCurrentContext()).ToLocalChecked();

#define ASSERT_BUFFER_SET_LENGTH(name, var) \
  ASSERT_BUFFER(name, var) \
  unsigned long long var##_length = CLENGTH(var);

#define ASSERT_BUFFER_MIN_LENGTH(name, var, length_name, length) \
  ASSERT_BUFFER_SET_LENGTH(name, var) \
  if (length > 0 && var##_length < length) { \
    Nan::ThrowError(#var " must be a buffer of size " #length_name); \
    return; \
  }

#define ASSERT_UINT(name, var) \
  if (!name->IsNumber()) { \
    Nan::ThrowError(#var " must be a number"); \
    return; \
  } \
  int64_t var = name.As<v8::Number>()->Value(); \
  if (var < 0) { \
    Nan::ThrowError(#var " must be at least 0"); \
    return; \
  }

#define ASSERT_UINT_BOUNDS(name, var, min_name, min, max_name, max) \
  if (!name->IsNumber()) { \
    Nan::ThrowError(#var " must be a number"); \
    return; \
  } \
  int64_t var = name.As<v8::Number>()->Value(); \
  \
  if (var < 0) { \
    Nan::ThrowError(#var " must be at least 0"); \
    return; \
  } \
  \
  if (((uint64_t) var) < min) { \
    Nan::ThrowError(#var " must be at least " #min_name); \
    return; \
  } \
  if (((uint64_t) var) > max) { \
    Nan::ThrowError(#var " must be at most " #max_name); \
    return; \
  }

#define ASSERT_FUNCTION(name, var) \
  if (!name->IsFunction()) { \
    Nan::ThrowError(#var " must be a function"); \
    return; \
  } \
  v8::Local<v8::Function> var = name.As<v8::Function>();

#define ASSERT_UNWRAP(name, var, type) \
  if (!name->IsObject()) { \
    Nan::ThrowError(#var " must be a " #type); \
    return; \
  } \
  type* var = Nan::ObjectWrap::Unwrap<type>(name->ToObject(v8::Isolate::GetCurrent()->GetCurrentContext()).ToLocalChecked());

#endif
