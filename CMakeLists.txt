cmake_minimum_required(VERSION 3.22)
project(cltls)

if(NOT DEFINED ARCH)
    set(ARCH x86_64)
endif()

string(TOLOWER ${ARCH} ARCH_LOWER)

include_directories(src/modules)
include_directories(src/modules/ctl)

if(ARCH_LOWER STREQUAL armv7_a)
    set(CMAKE_C_COMPILER "arm-linux-gnueabihf-gcc")
    link_directories(libs/armv7_a)
    set(LIB_ASCON_AEAD crypto_aead_ascon128av12_armv7m)
    set(LIB_ASCON_HASH crypto_hash_asconhashav12_armv7m)
    set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} "-std=c99 -O2 -Wall -static")
elseif(ARCH_LOWER STREQUAL x86_64)
    set(CMAKE_C_COMPILER "gcc")
    link_directories(libs/x86_64)
    set(LIB_ASCON_AEAD crypto_aead_ascon128av12_opt64)
    set(LIB_ASCON_HASH crypto_hash_asconhashav12_opt64)
    set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} "-std=c99 -O2 -Wall")
else()
    message(FATAL_ERROR "Unsupported arch: ${arch}")
endif()

file(GLOB_RECURSE SRC_MODULES "src/modules/*.c")

set(PACKAGE_LIST client server)

foreach(PACKAGE ${PACKAGE_LIST})
    file(GLOB_RECURSE SRC_PACKAGE "src/packages/${PACKAGE}/*.c")

    add_executable(cltls_${PACKAGE} ${SRC_MODULES} ${SRC_PACKAGE})

    target_link_libraries(cltls_${PACKAGE} PRIVATE ${LIB_ASCON_AEAD})
    target_link_libraries(cltls_${PACKAGE} PRIVATE ${LIB_ASCON_HASH})
    target_link_libraries(cltls_${PACKAGE} PRIVATE crypto)
endforeach()

set(MISC_EXECUTABLE_LIST initializer mqtt_client mqtt_server)

foreach(MISC_EXECUTABLE ${MISC_EXECUTABLE_LIST})
    file(GLOB SRC_MISC_EXECUTABLE "src/packages/misc/${MISC_EXECUTABLE}.c")

    if(MISC_EXECUTABLE MATCHES "^mqtt_.*")
        set(SRC_MISC_EXTRA "src/packages/misc/mqtt_common.c")
    endif()

    add_executable(cltls_misc_${MISC_EXECUTABLE} ${SRC_MODULES} ${SRC_MISC_EXECUTABLE} ${SRC_MISC_EXTRA})

    target_link_libraries(cltls_misc_${MISC_EXECUTABLE} PRIVATE ${LIB_ASCON_AEAD})
    target_link_libraries(cltls_misc_${MISC_EXECUTABLE} PRIVATE ${LIB_ASCON_HASH})
    target_link_libraries(cltls_misc_${MISC_EXECUTABLE} PRIVATE crypto)
endforeach()
