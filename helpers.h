/**
 * templates an minimal macros for jstl-fastcalls
 */
#include <assert.h>
#include <js.h>

#define SN_EXPORT_TYPED_FUNCTION(name, fn) \
  { \
    int err = js_set_property<fn>(env, exports, name); \
    assert(err == 0); \
  }

#define SN_ARG_OPT(name, use) \
  uint8_t *name##_data = NULL; \
  size_t name##_size = 0; \
  if (use) { \
    int err = js_get_typedarray_info(env, name, name##_data, name##_size); \
    assert(err == 0); \
  }

#define SN_ARG(name) \
  uint8_t *name##_data; \
  size_t name##_size; \
  { \
    int err = js_get_typedarray_info(env, name, name##_data, name##_size); \
    assert(err == 0); \
  }

#define SN_ARG_CAST(type, name, buffer) \
  type *name; \
  { \
    int err = js_get_typedarray_info<type>(env, buffer, name); \
    assert(err == 0); \
  }

#define SN_ARG_ISSET(name, bool_result) \
  { \
    js_value_type_t type; \
    int err = js_typeof(env, key, &type); \
    assert(err == 0); \
    bool_result = type != js_null && type != js_undefined; \
  }

#define SN_THROW(condition, message) \
  if ((condition)) { \
    int err = js_throw_error(env, NULL, message); \
    assert(err == 0); \
  }
#define SN_THROW_STATUS(status, callback_name) \
  SN_THROW((status) != 0, "\"" #callback_name "\" failed")
