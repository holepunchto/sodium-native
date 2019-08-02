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

napi_value sn_sodium_memcmp(napi_env env, napi_callback_info info) {
  NAPI_ARGV(2, sodium_memcmp);
  NAPI_TYPEDARRAY_ASSERT(b1, argv[0], "b1 must be instance of TypedArray");
  NAPI_TYPEDARRAY_ASSERT(b2, argv[1], "b1 must be instance of TypedArray");

  napi_typedarray_type b1_type;
  size_t b1_length;
  void * b1_data;

  napi_typedarray_type b2_type;
  size_t b2_length;
  void * b2_data;

  assert(napi_get_typedarray_info(env, argv[0], &b1_type, &b1_length, &b1_data, NULL, NULL) == napi_ok);

  uint8_t b1_width = typedarray_width(b1_type);
  NAPI_THROWS(b1_width == 0, "Unexpected TypedArray type");
  size_t b1_size = b1_length * b1_width;

  assert(napi_get_typedarray_info(env, argv[1], &b2_type, &b2_length, &b2_data, NULL, NULL) == napi_ok);

  uint8_t b2_width = typedarray_width(b2_type);
  NAPI_THROWS(b2_width == 0, "Unexpected TypedArray type");
  size_t b2_size = b2_length * b2_width;

  NAPI_THROWS(b1_size != b2_size, "buffers must be of same length");

  int cmp = sodium_memcmp(b1_data, b2_data, b1_size);

  napi_value result;
  assert(napi_get_boolean(env, cmp == 0, &result) == napi_ok);
  return result;
}

napi_value sn_sodium_increment(napi_env env, napi_callback_info info) {
  NAPI_ARGV(1, sodium_increment);
  NAPI_TYPEDARRAY_ASSERT(n, argv[0], "n must be an instance of TypedArray");

  NAPI_TYPEDARRAY(n, argv[0])

  sodium_increment(n_data, n_size);

  return NULL;
}

napi_value sn_sodium_add(napi_env env, napi_callback_info info) {
  NAPI_ARGV(2, sodium_add);
  NAPI_TYPEDARRAY_ASSERT(a, argv[0], "a must be an instance of TypedArray");
  NAPI_TYPEDARRAY_ASSERT(b, argv[1], "b must be an instance of TypedArray");

  NAPI_TYPEDARRAY(a, argv[0])
  NAPI_TYPEDARRAY(b, argv[1])

  NAPI_THROWS(a_size != b_size, "buffers must be of same length")
  sodium_add(a_data, b_data, a_size);

  return NULL;
}

napi_value create_sodium_native(napi_env env) {
  napi_value exports;
  assert(napi_create_object(env, &exports) == napi_ok);

  NAPI_EXPORT_FUNCTION(randombytes_uniform, sn_randombytes_uniform)
  NAPI_EXPORT_FUNCTION(randombytes_random, sn_randombytes_random)
  NAPI_EXPORT_FUNCTION(sodium_memcmp, sn_sodium_memcmp)
  NAPI_EXPORT_FUNCTION(sodium_increment, sn_sodium_increment)
  NAPI_EXPORT_FUNCTION(sodium_add, sn_sodium_add)

  return exports;
}

static napi_value Init(napi_env env, napi_value exports) {
  return create_sodium_native(env);
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
