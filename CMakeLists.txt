cmake_minimum_required(VERSION 3.12)
project(azure-kms-pkcs11)

add_executable(azure_kms_pkcs11 keyvault.cpp)
find_package(azure-security-keyvault-keys-cpp CONFIG REQUIRED)
find_package(azure-identity-cpp CONFIG REQUIRED)
target_link_libraries(azure_kms_pkcs11 PRIVATE Azure::azure-security-keyvault-keys Azure::azure-identity)