include_guard(GLOBAL)

if(WIN32)
  set(lib sodium.lib)
else()
  set(lib libsodium.a)
endif()

declare_port(
  "github:jedisct1/libsodium#a937222"
  sodium
  ZIG
  BYPRODUCTS lib/${lib}
  ARGS
    -Dstatic=true
    -Dshared=false
    -Dtest=false
  PATCHES
    patches/01-windows-sys-param.patch
)

add_library(sodium STATIC IMPORTED GLOBAL)

add_dependencies(sodium ${sodium})

set_target_properties(
  sodium
  PROPERTIES
  IMPORTED_LOCATION "${sodium_PREFIX}/lib/${lib}"
)

file(MAKE_DIRECTORY "${sodium_PREFIX}/include")

target_include_directories(
  sodium
  INTERFACE "${sodium_PREFIX}/include"
)

target_compile_definitions(
  sodium
  INTERFACE
    SODIUM_STATIC
)
