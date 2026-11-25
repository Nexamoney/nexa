# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.22.1)

message(STATUS "Nexa fullnode libnexa cmake is running")

set(CMAKE_C_FLAGS "")
set(CMAKE_C_FLAGS_DEBUG "")
set(CMAKE_C_FLAGS_RELEASE "")
set(CMAKE_CXX_FLAGS "")
set(CMAKE_CXX_FLAGS_DEBUG "")
set(CMAKE_CXX_FLAGS_RELEASE "")

set(CMAKE_VERBOSE_MAKEFILE ON)

# set(CMAKE_OSX_ARCHITECTURES "zzzzarm64" CACHE STRING "" FORCE)
# set(CMAKE_OSX_DEPLOYMENT_TARGET $ENV{CMAKE_OSX_DEPLOYMENT_TARGET} CACHE STRING "Min OSX ver")
set(CMAKE_OSX_DEPLOYMENT_TARGET "" CACHE STRING "Force unset of the deployment target for iOS" FORCE)
# set(CMAKE_OSX_SYSROOT $ENV{SYSROOT} CACHE STRING "target system root")
set(CMAKE_OSX_SYSROOT "" CACHE STRING "force unset of sysroot" FORCE)

set(COMPILE_OPTIONS "" CACHE STRING "" FORCE)
set(COMPILE_FLAGS "" CACHE STRING "" FORCE)

project(libnexa)
set(CMAKE_VERBOSE_MAKEFILE ON)
# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.


# HAVE_CONFIG_H: compat.h and compat/endian.h must see nexa-config.h before anything else defines HAVE_DECL_*
# BOOST_MP_STANDALONE: keep Boost.Multiprecision (cpp_int) from pulling in Boost.Math, whose fp_traits.hpp
#   static_asserts that x86 long double is 80 bits -- false on Android x86_64 (128-bit IEEE quad)
add_definitions(-DHAVE_CONFIG_H -DLIGHT -DBUILD_ONLY_LIBNEXA -DANDROID -Wno-tautological-constant-compare -DBOOST_SYSTEM_NO_DEPRECATED -DBOOST_MP_STANDALONE)

set(libsrc
             # Provides a relative path to your source file(s).
             libnexa.cpp
             libnexa_jvm.cpp
             libnexa_common.cpp
             libnexa_common.h
             ../config.cpp
             ../config.h
             ../base58.cpp
             ../script/interpreter.cpp
             ../script/op_parse.cpp
             ../script/script.cpp
             ../script/script.h
             ../script/scripttemplate.cpp
             ../script/scriptattributes.cpp
             ../script/stackitem.cpp
             ../script/pushtxstate.cpp
             ../script/merkleproof.cpp
             ../script/bignum.cpp
             ../script/script_error.cpp
             ../primitives/transaction.cpp
             ../primitives/block.cpp
             ../primitives/block.h
             ../support/pagelocker.cpp
             ../support/cleanse.cpp
             ../script/sigcommon.cpp
             ../script/bitfield.cpp
             ../script/bitfield.h
             ../capd/capdmsg.cpp
             ../capd/capd.h
             ../crypto/aes.cpp
             ../crypto/aes.h
             ../crypto/chacha20.cpp
             ../crypto/chacha20.h
             ../crypto/sha256.cpp
             ../crypto/hmac_sha512.cpp
             ../crypto/hmac_sha512.h
             ../crypto/sha512.cpp
             ../crypto/sha512.h
             ../crypto/ripemd160.cpp
             ../crypto/ripemd160.h
             ../crypto/sha1.cpp
             ../crypto/sha1.h
             ../dstencode.cpp
             ../dstencode.h
             ../pow.cpp
             ../hashwrapper.cpp
             ../hashwrapper.h
             ../key.cpp
             ../key.h
             ../uint256.cpp
             ../uint256.h
             ../utilstrencodings.cpp
             ../utilstrencodings.h
	     ../utilgrouptoken.cpp
             ../cashaddrenc.cpp
             ../cashaddrenc.h
             ../cashaddr.cpp
             ../cashaddr.h
             ../pubkey.cpp
             ../pubkey.h
             ../secp256k1/src/secp256k1.c
             ../chainparamsbase.cpp
             ../chainparams.cpp
             ../chainparams.h
             ../consensus/merkle.cpp
             ../consensus/grouptokens.cpp
             ../consensus/grouptokens.h
             ../arith_uint256.cpp
             ../arith_uint256.h
             ../bloom.cpp
             ../bloom.h
             ../merkleblock.cpp
             ../merkleblock.h
             ../streams.h
             ../random.cpp
             ../random.h
             ../randomenv.cpp
             ../randomenv.h
             ../validation/headervalidation.cpp
             )

# The script machine needs BigNum, which needs libgmp.  libgmp is built from source for the target ABI below.
# Configure with -DNO_SCRIPT_MACHINE=ON to build without the script machine (and libgmp).
option(NO_SCRIPT_MACHINE "Build without the script machine and libgmp" OFF)
if (NO_SCRIPT_MACHINE)
  add_definitions(-DNO_SCRIPT_MACHINE)
else()
  list(APPEND libsrc libnexa_script_machine.cpp libnexa_script_machine.h)
endif()

add_library(objlib OBJECT ${libsrc})
set_property(TARGET objlib PROPERTY POSITION_INDEPENDENT_CODE 1)
target_compile_features(objlib PRIVATE cxx_std_17)

# shared and static libraries built from the same object files
add_library(nexalight SHARED $<TARGET_OBJECTS:objlib>)
add_library(nexalighta STATIC $<TARGET_OBJECTS:objlib>)
target_compile_features(nexalight PRIVATE cxx_std_17)
target_compile_features(nexalighta PRIVATE cxx_std_17)

SET(OPT_SELECTION "-DVERIFY")
SET_SOURCE_FILES_PROPERTIES(../secp256k1/src/secp256k1.c PROPERTIES COMPILE_FLAGS ${OPT_SELECTION} )

# broken but should work
# set(Boost_USE_STATIC_LIBS OFF)
# set(Boost_USE_MULTITHREADED ON)
# set(Boost_USE_STATIC_RUNTIME OFF)
# set(Boost_DEBUG ON)
# set(Boost_NO_BOOST_CMAKE ON)
#set(BOOST_ROOT /fast/bitcoin/boostAndroid/boost_1_67_0)
#or maybe
#set(BOOST_ROOT /fast/bitcoin/boostAndroid/build/out/${ANDROID_ABI})
# set(BOOST_INCLUDEDIR /fast/bitcoin/boostAndroid/boost_1_67_0/boost)

#find_package(Boost 1.67.0 REQUIRED
#  COMPONENTS system
#  )
# HINTS /fast/bitcoin/boostAndroid/boost_1_67_0/boost
#)

# We expect that you have built boost in the libnexa subdirectory.  Run the ./buildBoostAndroid.sh script in the libnexa directory to do this.
set( Boost_LIB_DIR ${CMAKE_CURRENT_LIST_DIR}/boost/stage/lib)
set( Boost_INCLUDE_DIRS ${CMAKE_CURRENT_LIST_DIR}/boost)

# No boost libraries are currently needed (just the headers)
# file(GLOB F1 ${Boost_LIB_DIR}/libboost_thread-clang-mt-*-1_70.a)
# file(GLOB F2 ${Boost_LIB_DIR}/libboost_system-clang-mt-*-1_70.a)
#set( Boost_LIBRARIES ${F1} ${F2} )
set( Boost_LIBRARIES )

if (NOT NO_SCRIPT_MACHINE)
  include(ExternalProject)
  # keep version and hash in sync with downloadGmpLib.sh and depends/packages/libgmp.mk
  set(GMP_VERSION 6.3.0)
  set(GMP_SHA256 a3c2b80201b89e68616f4ad30bc66aee4927c3ce50e33929ca819d5c43538898)
  # use the archive fetched by downloadGmpLib.sh if it is there, otherwise download it
  if (EXISTS ${CMAKE_CURRENT_LIST_DIR}/gmp-${GMP_VERSION}.tar.xz)
    set(GMP_URL ${CMAKE_CURRENT_LIST_DIR}/gmp-${GMP_VERSION}.tar.xz)
  else()
    set(GMP_URL https://gmplib.org/download/gmp/gmp-${GMP_VERSION}.tar.xz)
  endif()

  # gmp configure --host triple for each ABI (same triples as the depends system uses)
  if (ANDROID_ABI STREQUAL "arm64-v8a")
    set(GMP_HOST --host=aarch64-linux-android)
  elseif (ANDROID_ABI STREQUAL "armeabi-v7a")
    set(GMP_HOST --host=armv7a-linux-androideabi)
  elseif (ANDROID_ABI STREQUAL "x86")
    set(GMP_HOST --host=i686-linux-android)
  elseif (ANDROID_ABI STREQUAL "x86_64")
    set(GMP_HOST --host=x86_64-linux-android)
  elseif (ANDROID_ABI STREQUAL "riscv64")
    set(GMP_HOST --host=riscv64-linux-android)
  elseif (ANDROID_ABI)
    message(FATAL_ERROR "No libgmp host triple for ANDROID_ABI ${ANDROID_ABI}")
  else()
    set(GMP_HOST "")  # not cross compiling
  endif()

  # Compile gmp with the same compiler (and target) as everything else
  set(GMP_CC "${CMAKE_C_COMPILER}")
  if (CMAKE_C_COMPILER_TARGET)
    string(APPEND GMP_CC " --target=${CMAKE_C_COMPILER_TARGET}")
  endif()
  if (CMAKE_SYSROOT)
    string(APPEND GMP_CC " --sysroot=${CMAKE_SYSROOT}")
  endif()

  set(GMP_PREFIX ${CMAKE_CURRENT_BINARY_DIR}/gmp)
  # DOWNLOAD_EXTRACT_TIMESTAMP only exists in cmake >= 3.24 (older versions misparse it as part of URL_HASH)
  set(GMP_EXTRACT_TIMESTAMP)
  if (CMAKE_VERSION VERSION_GREATER_EQUAL 3.24)
    set(GMP_EXTRACT_TIMESTAMP DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
  endif()
  # --disable-assembly: generic C only, as the depends build does for android
  ExternalProject_Add(gmp_build
    URL ${GMP_URL}
    URL_HASH SHA256=${GMP_SHA256}
    ${GMP_EXTRACT_TIMESTAMP}
    PREFIX ${CMAKE_CURRENT_BINARY_DIR}/gmp-ext
    CONFIGURE_COMMAND <SOURCE_DIR>/configure ${GMP_HOST} --prefix=${GMP_PREFIX}
        --disable-shared --enable-static --with-pic --disable-assembly
        "CC=${GMP_CC}" "CFLAGS=-O2 -fPIC" "AR=${CMAKE_AR}" "RANLIB=${CMAKE_RANLIB}"
    BUILD_COMMAND make -j8
    INSTALL_COMMAND make install
    BUILD_BYPRODUCTS ${GMP_PREFIX}/lib/libgmp.a
    )
  add_library(gmp STATIC IMPORTED)
  set_target_properties(gmp PROPERTIES IMPORTED_LOCATION ${GMP_PREFIX}/lib/libgmp.a)
  add_dependencies(gmp gmp_build)
  add_dependencies(objlib gmp_build)  # gmp.h must exist before compiling
  include_directories(${GMP_PREFIX}/include)
  set(GMP_LIBRARIES gmp)
else()
  set(GMP_LIBRARIES)
endif()

# The per-platform directory holding nexa-config.h.  BEFORE puts it first, so it wins over any stale
# nexa-config.h in the source tree.  Defaults to this directory, where nexa-config.h used to be copied.
set(NEXA_CONFIG_DIR ${CMAKE_CURRENT_LIST_DIR} CACHE PATH "Directory containing nexa-config.h")
include_directories(BEFORE ${NEXA_CONFIG_DIR})

include_directories( .
  ..
  ../script
  ../config
  ../secp256k1/include
  ../secp256k1
  ../secp256k1/src
  ${Boost_INCLUDE_DIRS}
  )

# Specifies libraries CMake should link to your target library. You
# can link multiple libraries, such as libraries you define in this
# build script, prebuilt third-party libraries, or system libraries.

# if you need boost libraries again someday
# set_target_properties(nexalight PROPERTIES LINK_FLAGS -L/fast/bitcoin/boostAndroid/build/out/${ANDROID_ABI}/lib)


#target_compile_features(nexalighta PRIVATE cxx_std_17)
SET(CMAKE_CXX_FLAGS  "-std=c++17 ${CMAKE_CXX_FLAGS}")

target_link_libraries( # Specifies the target library.
                       nexalight
                       # Links the target library to these libraries
                       ${GMP_LIBRARIES}
                       android  # base android library
                       log  # android log library
                       # ${Boost_LIBRARIES}
                       )

target_link_libraries( # Specifies the target library.
                       nexalighta
                       # Links the target library to these libraries
                       ${GMP_LIBRARIES}
                       android  # base android library
                       log  # android log library
                       c++_static
                       # ${Boost_LIBRARIES}
                       )
