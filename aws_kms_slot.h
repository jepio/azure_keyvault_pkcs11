#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <openssl/x509.h>

using std::string;

class AwsKmsSlot {
private:
    string label;
    string vault_name;
    string key_name;
    string key_id;
    bool public_key_data_fetched;
    std::vector<uint8_t> public_key_data;
    X509* certificate;
public:
    AwsKmsSlot(string label, string key_name, string vault_name, X509* certificate);
    string GetLabel();
    string GetKeyName();
    string GetVaultName();
    X509* GetCertificate();
    string GetKeyId();
    std::vector<uint8_t> GetPublicKeyData();
};
