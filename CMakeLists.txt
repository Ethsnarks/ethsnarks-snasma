cmake_minimum_required(VERSION 3.9)
project(ethsnarks-example-signatures)
add_subdirectory(ethsnarks ethsnarks EXCLUDE_FROM_ALL)

add_executable(snasmad main.cpp)
target_link_libraries(snasmad ethsnarks_jubjub)
