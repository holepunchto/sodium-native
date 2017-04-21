#ifndef SODIDUM_NATIVE_MACROS_H
#define SODIDUM_NATIVE_MACROS_H

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define CDATA(buf) (unsigned char *) node::Buffer::Data(buf)
#define CLENGTH(buf) (unsigned long long) node::Buffer::Length(buf)
#define LOCAL_STRING(str) Nan::New<String>(str).ToLocalChecked()
#define LOCAL_FUNCTION(fn) Nan::GetFunction(Nan::New<FunctionTemplate>(fn)).ToLocalChecked()
#define EXPORT_NUMBER(name) Nan::Set(target, LOCAL_STRING(#name), Nan::New<Number>(name));
#define EXPORT_STRING(name) Nan::Set(target, LOCAL_STRING(#name), LOCAL_STRING(name));
#define EXPORT_FUNCTION(name) Nan::Set(target, LOCAL_STRING(#name), LOCAL_FUNCTION(name));

// workaround for old compilers
#ifndef SIZE_MAX
#define SIZE_MAX ((size_t) - 1)
#endif

#define CALL_SODIUM(fn) \
  int ret = fn; \
  if (ret) { \
    Nan::ThrowError("Sodium operation failed"); \
    return; \
  }

#define CALL_SODIUM_BOOL(fn) \
  int ret = fn; \
  info.GetReturnValue().Set(ret == 0 ? Nan::True() : Nan::False());

#define ASSERT_BUFFER(name, var) \
  if (!name->IsObject()) { \
    Nan::ThrowError(#var " must be a buffer"); \
    return; \
  } \
  Local<Object> var = name->ToObject();

#define ASSERT_BUFFER_SET_LENGTH(name, var) \
  ASSERT_BUFFER(name, var) \
  unsigned long long var##_length = CLENGTH(var);

#define ASSERT_BUFFER_MIN_LENGTH(name, var, length) \
  ASSERT_BUFFER_SET_LENGTH(name, var) \
  if (var##_length < length) { \
    Nan::ThrowError(#var " must be a buffer of size " STR(length)); \
    return; \
  }

#define ASSERT_UINT(name, var) \
  if (!name->IsNumber()) { \
    Nan::ThrowError(#var " must be a number"); \
    return; \
  } \
  unsigned int var = name->Uint32Value();

#define ASSERT_UINT_BOUNDS(name, var, min, max) \
  if (!name->IsNumber()) { \
    Nan::ThrowError(#var " must be a number"); \
    return; \
  } \
  unsigned int var = name->Uint32Value(); \
  \
  if (var < min) { \
    Nan::ThrowError(#var "must be at least " #min); \
    return; \
  } \
  if (((unsigned long long) var) > max) { \
    Nan::ThrowError(#var "must be at most " #max); \
    return; \
  }

#define ASSERT_FUNCTION(name, var) \
  if (!name->IsFunction()) { \
    Nan::ThrowError(#var " must be a function"); \
    return; \
  } \
  Local<Function> var = name.As<Function>();

#endif
