#include "crypto_generichash_wrap.h"
#include <node_buffer.h>

static Nan::Persistent<FunctionTemplate> crypto_generichash_constructor;

CryptoGenericHashWrap::CryptoGenericHashWrap () {
  // inited in NewInstance
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

  if (!info[0]->IsObject()) {
    Nan::ThrowError("input must be a buffer");
    return;
  }

  Local<Object> input = info[0]->ToObject();
  crypto_generichash_update(self->state, (unsigned char *) node::Buffer::Data(input), node::Buffer::Length(input));
}

NAN_METHOD(CryptoGenericHashWrap::Final) {
  CryptoGenericHashWrap *self = Nan::ObjectWrap::Unwrap<CryptoGenericHashWrap>(info.This());

  if (!info[0]->IsObject()) {
    Nan::ThrowError("output must be a buffer");
    return;
  }

  Local<Object> output = info[0]->ToObject();
  crypto_generichash_final(self->state, (unsigned char *) node::Buffer::Data(output), node::Buffer::Length(output));
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
