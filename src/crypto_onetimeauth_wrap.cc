#include "crypto_onetimeauth_wrap.h"
#include "macros.h"

static Nan::Persistent<FunctionTemplate> crypto_onetimeauth_constructor;

CryptoOnetimeAuthWrap::CryptoOnetimeAuthWrap () {
  this->state = NULL;
}

CryptoOnetimeAuthWrap::~CryptoOnetimeAuthWrap () {
  sodium_free(this->state);
}

NAN_METHOD(CryptoOnetimeAuthWrap::New) {
  CryptoOnetimeAuthWrap* obj = new CryptoOnetimeAuthWrap();
  obj->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(CryptoOnetimeAuthWrap::Update) {
  CryptoOnetimeAuthWrap *self = Nan::ObjectWrap::Unwrap<CryptoOnetimeAuthWrap>(info.This());
  ASSERT_BUFFER_SET_LENGTH(info[0], input)
  crypto_onetimeauth_update(self->state, CDATA(input), input_length);
}

NAN_METHOD(CryptoOnetimeAuthWrap::Final) {
  CryptoOnetimeAuthWrap *self = Nan::ObjectWrap::Unwrap<CryptoOnetimeAuthWrap>(info.This());
  ASSERT_BUFFER_MIN_LENGTH(info[0], output, crypto_onetimeauth_BYTES)
  crypto_onetimeauth_final(self->state, CDATA(output));
}

void CryptoOnetimeAuthWrap::Init () {
  Local<FunctionTemplate> tpl = Nan::New<FunctionTemplate>(CryptoOnetimeAuthWrap::New);
  crypto_onetimeauth_constructor.Reset(tpl);
  tpl->SetClassName(Nan::New("CryptoOnetimeAuthWrap").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "update", CryptoOnetimeAuthWrap::Update);
  Nan::SetPrototypeMethod(tpl, "final", CryptoOnetimeAuthWrap::Final);
}

Local<Value> CryptoOnetimeAuthWrap::NewInstance (unsigned char *key) {
  Nan::EscapableHandleScope scope;

  Local<Object> instance;

  Local<FunctionTemplate> constructorHandle = Nan::New<FunctionTemplate>(crypto_onetimeauth_constructor);
  instance = constructorHandle->GetFunction()->NewInstance(0, NULL);

  CryptoOnetimeAuthWrap *self = Nan::ObjectWrap::Unwrap<CryptoOnetimeAuthWrap>(instance);
  self->state = (crypto_onetimeauth_state*) sodium_malloc(crypto_onetimeauth_statebytes());
  crypto_onetimeauth_init(self->state, key);

  return scope.Escape(instance);
}
