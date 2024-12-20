cmake_minimum_required(VERSION 3.10)
project(azure-keyvault-pkcs11)

set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_SHARED_MODULE_PREFIX "")

find_package(azure-identity-cpp CONFIG REQUIRED)
find_package(azure-security-keyvault-keys-cpp CONFIG REQUIRED)
find_package(azure-security-keyvault-certificates-cpp CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)

set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
find_package(json-c CONFIG)
pkg_check_modules(P11_KIT REQUIRED IMPORTED_TARGET p11-kit-1)

set(SRC ${CMAKE_CURRENT_SOURCE_DIR}/../src)

add_library(azure-keyvault-pkcs11 MODULE
  ${SRC}/attributes.cpp
  ${SRC}/azure-keyvault-pkcs11.cpp
  ${SRC}/azure-keyvault-slot.cpp
  ${SRC}/certificates.cpp
  ${SRC}/debug.cpp
  ${SRC}/unsupported.cpp
)
target_include_directories(azure-keyvault-pkcs11 PRIVATE
  ${SRC}
  ${P11_KIT_INCLUDE_DIRS}/p11-kit
)
target_link_libraries(azure-keyvault-pkcs11 PRIVATE
  Azure::azure-security-keyvault-keys
  Azure::azure-security-keyvault-certificates
  Azure::azure-identity
  json-c::json-c
  OpenSSL::Crypto
  OpenSSL::SSL
  -Wl,--version-script=${SRC}/azure-keyvault-pkcs11.version
  -Wl,-z,defs
  -Wl,--as-needed
  -Wl,-O1
  -Wl,-Bsymbolic
  -static-libstdc++
)
