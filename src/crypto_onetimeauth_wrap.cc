#include "crypto_onetimeauth_wrap.h"
#include <node_buffer.h>

static Nan::Persistent<FunctionTemplate> crypto_onetimeauth_constructor;

CryptoOnetimeAuthWrap::CryptoOnetimeAuthWrap () {
  // inited in NewInstance
}

CryptoOnetimeAuthWrap::~CryptoOnetimeAuthWrap () {
  free(this->state);
}

NAN_METHOD(CryptoOnetimeAuthWrap::New) {
  CryptoOnetimeAuthWrap* obj = new CryptoOnetimeAuthWrap();
  obj->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(CryptoOnetimeAuthWrap::Update) {
  CryptoOnetimeAuthWrap *self = Nan::ObjectWrap::Unwrap<CryptoOnetimeAuthWrap>(info.This());

  if (!info[0]->IsObject()) {
    Nan::ThrowError("input must be a buffer");
    return;
  }

  Local<Object> input = info[0]->ToObject();
  crypto_onetimeauth_update(self->state, (unsigned char *) node::Buffer::Data(input), node::Buffer::Length(input));
}

NAN_METHOD(CryptoOnetimeAuthWrap::Final) {
  CryptoOnetimeAuthWrap *self = Nan::ObjectWrap::Unwrap<CryptoOnetimeAuthWrap>(info.This());

  if (!info[0]->IsObject()) {
    Nan::ThrowError("output must be a buffer");
    return;
  }

  Local<Object> output = info[0]->ToObject();

  // Local<Object> output = info[0]->ToObject();
  if (node::Buffer::Length(output) < crypto_onetimeauth_BYTES) {
    Nan::ThrowError("output must be at least 16 bytes");
    return;
  }

  crypto_onetimeauth_final(self->state, (unsigned char *) node::Buffer::Data(output));
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
  self->state = (crypto_onetimeauth_state *) malloc(sizeof(crypto_onetimeauth_state));
  crypto_onetimeauth_init(self->state, key);

  return scope.Escape(instance);
}
