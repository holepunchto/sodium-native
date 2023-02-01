cmake_minimum_required(VERSION 3.25)

project(sodium_native C)

include(pear)

add_pear_module(sodium_native)

target_sources(
  sodium_native
  PUBLIC
    binding.c
)

execute_process(
  COMMAND node deps/bin.js --print-include
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  OUTPUT_VARIABLE sodium_include
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

execute_process(
  COMMAND node deps/bin.js --print-lib
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  OUTPUT_VARIABLE sodium
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

target_include_directories(
  sodium_native
  PUBLIC
    ${sodium_include}
)

target_link_libraries(
  sodium_native
  PUBLIC
    ${sodium}
)
