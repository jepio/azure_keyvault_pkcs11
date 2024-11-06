cmake_minimum_required(VERSION 3.10)
project(azure-kms-pkcs11)

set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_SHARED_MODULE_PREFIX "")

find_package(azure-identity-cpp CONFIG REQUIRED)
find_package(azure-security-keyvault-keys-cpp CONFIG REQUIRED)
find_package(azure-security-keyvault-certificates-cpp CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
#pkg_check_modules(JSON_C REQUIRED IMPORTED_TARGET json-c)
pkg_check_modules(P11_KIT REQUIRED IMPORTED_TARGET p11-kit-1)
find_package(json-c CONFIG)

set(DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)

add_library(azure_kms_pkcs11 MODULE
	${DIR}/aws_kms_pkcs11.cpp
	${DIR}/unsupported.cpp
	${DIR}/aws_kms_slot.cpp
	${DIR}/debug.cpp
	${DIR}/attributes.cpp
	${DIR}/certificates.cpp
)
target_include_directories(azure_kms_pkcs11 PRIVATE
	${DIR}
	${P11_KIT_INCLUDE_DIRS}/p11-kit
)
target_link_libraries(azure_kms_pkcs11 PRIVATE
	Azure::azure-security-keyvault-keys
	Azure::azure-security-keyvault-certificates
	Azure::azure-identity
	json-c::json-c
	OpenSSL::Crypto
	OpenSSL::SSL
	-Wl,--version-script=${DIR}/azure_kms_pkcs11.version
	-Wl,-z,defs
	-Wl,--as-needed
	-Wl,-O1
	-Wl,-Bsymbolic
	-static-libstdc++
)
