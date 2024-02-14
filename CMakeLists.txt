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
include_directories(src/modules/ctl)
link_directories(libs)

if(ARCH_LOWER STREQUAL arm32)
    set(LIB_SUFFIX_ASCON opt32_eabi)
    set(LIB_SUFFIX_BORINGSSL eabi)
elseif(ARCH_LOWER STREQUAL x86_64)
    set(LIB_SUFFIX_ASCON opt64_x64)
    set(LIB_SUFFIX_BORINGSSL x64)
endif()

file(GLOB_RECURSE SRC_MODULES "src/modules/*.c" "src/modules/*.h")

set(PACKAGE_LIST client server)

foreach(PACKAGE ${PACKAGE_LIST})
    file(GLOB_RECURSE SRC_PACKAGE "src/packages/${PACKAGE}/*.c" "src/packages/${PACKAGE}/*.h")

    add_executable(cltls_${PACKAGE} ${SRC_MODULES} ${SRC_PACKAGE})

    target_link_libraries(cltls_${PACKAGE} PRIVATE crypto_aead_ascon128av12_${LIB_SUFFIX_ASCON})
    target_link_libraries(cltls_${PACKAGE} PRIVATE crypto_hash_asconhashav12_${LIB_SUFFIX_ASCON})
    target_link_libraries(cltls_${PACKAGE} PRIVATE crypto_boringssl_${LIB_SUFFIX_BORINGSSL})
endforeach()

if(ARCH_LOWER STREQUAL arm32)
    set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} "-std=c99 -O2 -Wall -static")
else()
    set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} "-std=c99 -O2 -Wall")
endif()