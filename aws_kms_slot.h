#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <openssl/x509.h>

using std::string;

class AwsKmsSlot {
private:
    const string label;
    const string key_name;
    const string vault_name;
    const X509* certificate;
    bool public_key_data_fetched;
    std::vector<uint8_t> public_key_data;
    string key_id;
    unsigned int key_size;
    void FetchPublicKeyData();

public:
    AwsKmsSlot(const string &label, const string &key_name, const string &vault_name,
               const X509* certificate);
    const string& GetLabel();
    const string& GetKeyName();
    const string& GetVaultName();
    const X509* GetCertificate();
    std::vector<uint8_t> GetPublicKeyData();
    const string& GetKeyId();
    const unsigned int GetKeySize();
};
