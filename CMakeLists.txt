cmake_minimum_required(VERSION 3.31)

find_package(cmake-bare REQUIRED PATHS node_modules/cmake-bare)
find_package(cmake-napi REQUIRED PATHS node_modules/cmake-napi)
find_package(cmake-npm REQUIRED PATHS node_modules/cmake-npm)
find_package(cmake-ports REQUIRED PATHS node_modules/cmake-ports)

project(sodium_native C CXX ASM)

fetch_package("github:holepunchto/libjstl#098664c")

find_port(libsodium)

add_library(sodium_extensions OBJECT)

target_sources(
  sodium_extensions
  PRIVATE
    extensions/tweak/tweak.c
    extensions/tweak/tweak.h
    extensions/pbkdf2/pbkdf2.c
    extensions/pbkdf2/pbkdf2.h
)

target_link_libraries(
  sodium_extensions
  PUBLIC
    sodium
)

add_bare_module(sodium_native_bare)

target_sources(
  ${sodium_native_bare}
  PRIVATE
    binding.cc
)

target_link_libraries(
  ${sodium_native_bare}
  PRIVATE
    $<TARGET_OBJECTS:sodium>
    $<TARGET_OBJECTS:sodium_extensions>
    jstl
  PUBLIC
    sodium
    sodium_extensions
)

add_napi_module(sodium_native_node)

target_sources(
  ${sodium_native_node}
  PRIVATE
    binding.cc
)

target_compile_definitions(
  ${sodium_native_node}
  PRIVATE
    NAPI_VERSION=9
)

target_link_libraries(
  ${sodium_native_node}
  PRIVATE
    $<TARGET_OBJECTS:sodium>
    $<TARGET_OBJECTS:sodium_extensions>
    jstl
  PUBLIC
    sodium
    sodium_extensions
)

resolve_node_module(bare-compat-napi compat)

target_include_directories(
  ${sodium_native_node}
  PRIVATE
    "${compat}/include"
)
