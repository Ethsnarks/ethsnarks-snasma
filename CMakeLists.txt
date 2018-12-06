cmake_minimum_required(VERSION 2.8)
project(ethsnarks-example-signatures)
add_subdirectory(ethsnarks ethsnarks EXCLUDE_FROM_ALL)

add_executable(example-signatures example_signatures.cpp)
target_link_libraries(example-signatures ethsnarks_jubjub)
