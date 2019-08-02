#include <node_api.h>
#include <assert.h>
#include "macros.h"
#include <sodium.h>

napi_value sn_randombytes_random (napi_env env, napi_callback_info info) {
  napi_value result;

  assert(napi_create_uint32(env, randombytes_random(), &result) == napi_ok);
  return result;
}

napi_value sn_randombytes_uniform (napi_env env, napi_callback_info info) {
  NAPI_ARGV(1, randombytes_uniform);
  NAPI_TYPE_ASSERT(upper_bound, argv[0], napi_number, "upper_bound must be a Number");

  uint32_t upper_bound;
  assert(napi_get_value_uint32(env, argv[0], &upper_bound) == napi_ok);

  napi_value result;
  assert(napi_create_uint32(env, randombytes_uniform(upper_bound), &result) == napi_ok);
  return result;
}

uint8_t typedarray_width(napi_typedarray_type type) {
  switch (type) {
    case napi_int8_array: return 1;
    case napi_uint8_array: return 1;
    case napi_uint8_clamped_array: return 1;
    case napi_int16_array: return 2;
    case napi_uint16_array: return 2;
    case napi_int32_array: return 4;
    case napi_uint32_array: return 4;
    case napi_float32_array: return 4;
    case napi_float64_array: return 8;
    case napi_bigint64_array: return 8;
    case napi_biguint64_array: return 8;
    default: return 0;
  }
}

napi_value sn_randombytes_buf (napi_env env, napi_callback_info info) {
  NAPI_ARGV(1, randombytes_buf)
  NAPI_TYPEDARRAY_ASSERT(buf, argv[0], "buf must be an TypedArray")

  napi_typedarray_type type;
  size_t length;
  void * data;

  assert(napi_get_typedarray_info(env, argv[0], &type, &length, &data, NULL, NULL) == napi_ok);

  uint8_t width = typedarray_width(type);
  NAPI_THROWS(width == 0, "Unexpected TypedArray type")
  size_t size = length * width;

  randombytes_buf(data, size);

  return NULL;
}

napi_value create_sodium_native(napi_env env) {
  napi_value exports;
  assert(napi_create_object(env, &exports) == napi_ok);

  NAPI_EXPORT_FUNCTION(randombytes_uniform, sn_randombytes_uniform)
  NAPI_EXPORT_FUNCTION(randombytes_random, sn_randombytes_random)
  NAPI_EXPORT_FUNCTION(randombytes_buf, sn_randombytes_buf)
  NAPI_EXPORT_UINT32(randombytes_SEEDBYTES, randombytes_seedbytes())
  return exports;
}

static napi_value Init(napi_env env, napi_value exports) {
  return create_sodium_native(env);
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
