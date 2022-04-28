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
    const string label;
    const string key_name;
    const string vault_name;
    const X509* certificate;
    bool public_key_data_fetched;
    std::vector<uint8_t> public_key_data;
    unsigned int key_size;
    std::unique_ptr<Azure::Security::KeyVault::Keys::KeyClient> key_client;
    void FetchPublicKeyData();

public:
    AwsKmsSlot(const string &label, const string &key_name, const string &vault_name,
               const X509* certificate);
    const string& GetLabel();
    const string& GetKeyName();
    const string& GetVaultName();
    const X509* GetCertificate();
    std::vector<uint8_t> GetPublicKeyData();
    const unsigned int GetKeySize();
    Azure::Security::KeyVault::Keys::Cryptography::CryptographyClient GetCryptoClient();
};
