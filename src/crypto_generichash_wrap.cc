#include "crypto_generichash_wrap.h"
#include "macros.h"

static Nan::Persistent<FunctionTemplate> crypto_generichash_constructor;

CryptoGenericHashWrap::CryptoGenericHashWrap () {
  this->state = NULL;
}

CryptoGenericHashWrap::~CryptoGenericHashWrap () {
  free(this->state);
}

NAN_METHOD(CryptoGenericHashWrap::New) {
  CryptoGenericHashWrap* obj = new CryptoGenericHashWrap();
  obj->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(CryptoGenericHashWrap::Update) {
  CryptoGenericHashWrap *self = Nan::ObjectWrap::Unwrap<CryptoGenericHashWrap>(info.This());
  ASSERT_BUFFER_SET_LENGTH(info[0], input)
  crypto_generichash_update(self->state, CDATA(input), input_length);
}

NAN_METHOD(CryptoGenericHashWrap::Final) {
  CryptoGenericHashWrap *self = Nan::ObjectWrap::Unwrap<CryptoGenericHashWrap>(info.This());
  ASSERT_BUFFER_MIN_LENGTH(info[0], output, crypto_generichash_BYTES_MIN)
  crypto_generichash_final(self->state, CDATA(output), output_length);
}

void CryptoGenericHashWrap::Init () {
  Local<FunctionTemplate> tpl = Nan::New<FunctionTemplate>(CryptoGenericHashWrap::New);
  crypto_generichash_constructor.Reset(tpl);
  tpl->SetClassName(Nan::New("CryptoGenericHashWrap").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "update", CryptoGenericHashWrap::Update);
  Nan::SetPrototypeMethod(tpl, "final", CryptoGenericHashWrap::Final);
}

Local<Value> CryptoGenericHashWrap::NewInstance (unsigned char *key, unsigned long long key_length, unsigned long long output_length) {
  Nan::EscapableHandleScope scope;

  Local<Object> instance;

  Local<FunctionTemplate> constructorHandle = Nan::New<FunctionTemplate>(crypto_generichash_constructor);
  instance = constructorHandle->GetFunction()->NewInstance(0, NULL);

  CryptoGenericHashWrap *self = Nan::ObjectWrap::Unwrap<CryptoGenericHashWrap>(instance);
  self->state = (crypto_generichash_blake2b_state *) malloc(sizeof(crypto_generichash_state));
  crypto_generichash_init(self->state, key, key_length, output_length);

  return scope.Escape(instance);
}
