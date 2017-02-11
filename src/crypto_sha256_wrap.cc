#include "crypto_hash_sha256_wrap.h"
#include "macros.h"

static Nan::Persistent<FunctionTemplate> crypto_hash_sha256_constructor;

CryptoSha256Wrap::CryptoSha256Wrap () {
  this->state = NULL;
}

CryptoSha256Wrap::~CryptoSha256Wrap () {
  sodium_free(this->state);
}

NAN_METHOD(CryptoSha256Wrap::New) {
  CryptoSha256Wrap* obj = new CryptoSha256Wrap();
  obj->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(CryptoSha256Wrap::Update) {
  CryptoSha256Wrap *self = Nan::ObjectWrap::Unwrap<CryptoSha256Wrap>(info.This());
  ASSERT_BUFFER_SET_LENGTH(info[0], input)
  crypto_hash_sha256_update(&(self->state), CDATA(input), input_length);
}

NAN_METHOD(CryptoSha256Wrap::Final) {
  CryptoSha256Wrap *self = Nan::ObjectWrap::Unwrap<CryptoSha256Wrap>(info.This());
  ASSERT_BUFFER_MIN_LENGTH(info[0], output, crypto_hash_sha256_BYTES)
  crypto_hash_sha256_final(&(self->state), CDATA(output), output_length);
}

void CryptoSha256Wrap::Init () {
  Local<FunctionTemplate> tpl = Nan::New<FunctionTemplate>(CryptoSha256Wrap::New);
  crypto_hash_sha256_constructor.Reset(tpl);
  tpl->SetClassName(Nan::New("CryptoSha256Wrap").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "update", CryptoSha256Wrap::Update);
  Nan::SetPrototypeMethod(tpl, "final", CryptoSha256Wrap::Final);
}

Local<Value> CryptoSha256Wrap::NewInstance () {
  Nan::EscapableHandleScope scope;

  Local<Object> instance;

  Local<FunctionTemplate> constructorHandle = Nan::New<FunctionTemplate>(crypto_hash_sha256_constructor);
  instance = Nan::NewInstance(constructorHandle->GetFunction()).ToLocalChecked();

  CryptoSha256Wrap *self = Nan::ObjectWrap::Unwrap<CryptoSha256Wrap>(instance);
  crypto_hash_sha256_init(&(self->state));

  return scope.Escape(instance);
}
