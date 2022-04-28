#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <openssl/x509.h>

#include <azure/keyvault/keys/key_client.hpp>
#include <azure/keyvault/keys/cryptography/cryptography_client.hpp>

using std::string;

class AwsKmsSlot {
private:
    string label;
    string vault_name;
    string key_name;
    bool public_key_data_fetched;
    std::vector<uint8_t> public_key_data;
    std::unique_ptr<Azure::Security::KeyVault::Keys::KeyClient> key_client;
    X509* certificate;
public:
    AwsKmsSlot(string label, string key_name, string vault_name, X509* certificate);
    string GetLabel();
    string GetKeyName();
    string GetVaultName();
    X509* GetCertificate();
    std::vector<uint8_t> GetPublicKeyData();
    Azure::Security::KeyVault::Keys::Cryptography::CryptographyClient  GetCryptoClient();
};
