include_guard(GLOBAL)

declare_port(
  "github:jedisct1/libsodium#a937222"
  sodium
  ZIG
  BYPRODUCTS lib/libsodium.a
  ARGS
    -Dstatic=true
    -Dshared=false
    -Dtest=false
)

add_library(sodium STATIC IMPORTED GLOBAL)

add_dependencies(sodium ${sodium})

set_target_properties(
  sodium
  PROPERTIES
  IMPORTED_LOCATION "${sodium_PREFIX}/lib/libsodium.a"
)

file(MAKE_DIRECTORY "${sodium_PREFIX}/include")

target_include_directories(
  sodium
  INTERFACE "${sodium_PREFIX}/include"
)
