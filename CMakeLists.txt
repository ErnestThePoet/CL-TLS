cmake_minimum_required(VERSION 3.22)
project(cltls)

if(NOT DEFINED ARCH)
    set(ARCH x86_64)
endif()

string(TOLOWER ${ARCH} ARCH_LOWER)

if(ARCH_LOWER STREQUAL arm32)
    set(CMAKE_C_COMPILER "arm-linux-gnueabihf-gcc")
elseif(ARCH_LOWER STREQUAL x86_64)
    set(CMAKE_C_COMPILER "gcc")
else()
    message(FATAL_ERROR "Unsupported arch: ${arch}")
endif()

include_directories(src/modules)
link_directories(libs)

if(ARCH_LOWER STREQUAL arm32)
    set(LIB_SUFFIX eabi)
elseif(ARCH_LOWER STREQUAL x86_64)
    set(LIB_SUFFIX x64)
endif()

file(GLOB_RECURSE SRC_MODULES "src/modules/*.c" "src/modules/*.h")

set(PACKAGES client server)

foreach(PACKAGE ${PACKAGES})
    file(GLOB_RECURSE SRC_PACKAGE "src/packages/${PACKAGE}/*.c" "src/packages/${PACKAGE}/*.h")

    add_executable(cltls_${PACKAGES} ${SRC_MODULES} ${SRC_PACKAGE})

    target_link_libraries(cltls_${PACKAGES} PRIVATE crypto_aead_ascon128av12_opt64_${LIB_SUFFIX})
    target_link_libraries(cltls_${PACKAGES} PRIVATE crypto_hash_asconxofav12_opt64_${LIB_SUFFIX})
    target_link_libraries(cltls_${PACKAGES} PRIVATE crypto_boringssl_${LIB_SUFFIX})
endforeach()

set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} "-std=c99 -O2 -Wall")

if(ARCH_LOWER STREQUAL arm32)
    set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} "-static")
endif()