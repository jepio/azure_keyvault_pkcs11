cmake_minimum_required(VERSION 3.12)
project(azure-kms-pkcs11)

set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_SHARED_MODULE_PREFIX "")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
#set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
#set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -fsanitize=address")

find_package(azure-security-keyvault-keys-cpp CONFIG REQUIRED)
find_package(azure-identity-cpp CONFIG REQUIRED)
find_package(PkgConfig REQUIRED)

set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
pkg_check_modules(P11_KIT REQUIRED IMPORTED_TARGET p11-kit-1)
pkg_check_modules(JSON_C REQUIRED IMPORTED_TARGET json-c)

add_executable(keyvault keyvault.cpp)
target_link_libraries(keyvault PRIVATE -static-libstdc++ Azure::azure-security-keyvault-keys Azure::azure-identity)

add_library(azure_kms_pkcs11 MODULE
  aws_kms_pkcs11.cpp
  unsupported.cpp
  aws_kms_slot.cpp
  debug.cpp
  attributes.cpp
  certificates.cpp
)
target_include_directories(azure_kms_pkcs11 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(azure_kms_pkcs11 PRIVATE
  -static-libstdc++
  Azure::azure-security-keyvault-keys
  Azure::azure-identity
  PkgConfig::JSON_C
  -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/azure_kms_pkcs11.version
)
target_include_directories(azure_kms_pkcs11 PRIVATE ${P11_KIT_INCLUDE_DIRS}/p11-kit)

#add_executable(example example.cpp)
#target_link_libraries(example PRIVATE azure_kms_pkcs11)

add_executable(aws_kms_pkcs11_test aws_kms_pkcs11_test.c)
target_include_directories(aws_kms_pkcs11_test PRIVATE ${P11_KIT_INCLUDE_DIRS}/p11-kit)
target_link_libraries(aws_kms_pkcs11_test PRIVATE -ldl)

include(GNUInstallDirs)
install(TARGETS azure_kms_pkcs11 LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkcs11/)
