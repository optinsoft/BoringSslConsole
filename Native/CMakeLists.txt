cmake_minimum_required(VERSION 3.22)
project(proxymap_boringssl LANGUAGES C CXX)

if (NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../boringssl/CMakeLists.txt")
    message(FATAL_ERROR "BoringSSL was not found. Clone it into ../boringssl")
endif()

add_subdirectory(
    "${CMAKE_CURRENT_SOURCE_DIR}/../boringssl"
    "${CMAKE_BINARY_DIR}/boringssl"
    EXCLUDE_FROM_ALL)

add_library(proxymap_boringssl SHARED ssl_wrapper.cc)

target_include_directories(proxymap_boringssl PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../boringssl/include")

target_link_libraries(proxymap_boringssl PRIVATE ssl crypto)

target_compile_features(proxymap_boringssl PRIVATE cxx_std_17)

if (MSVC)
    target_compile_options(proxymap_boringssl PRIVATE /W4)
else()
    target_compile_options(proxymap_boringssl PRIVATE -Wall -Wextra)
endif()
