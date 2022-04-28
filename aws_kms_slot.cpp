#include <azure/keyvault/keys/key_client.hpp>
#include <azure/identity/environment_credential.hpp>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <string>

#include "aws_kms_slot.h"
#include "debug.h"

using std::string;

AwsKmsSlot::AwsKmsSlot(string label, string key_name, string vault_name, X509* certificate) {
    this->label = label;
    this->key_name = key_name;
    this->vault_name = vault_name;
    this->public_key_data_fetched = false;
    this->certificate = certificate;
    auto credential = std::make_shared<Azure::Identity::EnvironmentCredential>();
    this->key_client = std::make_unique<Azure::Security::KeyVault::Keys::KeyClient>(this->vault_name, credential);
}
string AwsKmsSlot::GetLabel() {
    return this->label;
}
string AwsKmsSlot::GetVaultName() {
    return this->vault_name;
}
string AwsKmsSlot::GetKeyName() {
    return this->key_name;
}
X509* AwsKmsSlot::GetCertificate() {
    return this->certificate;
}
Azure::Security::KeyVault::Keys::Cryptography::CryptographyClient AwsKmsSlot::GetCryptoClient() {
    return this->key_client->GetCryptographyClient(this->key_name);
}
std::vector<uint8_t> AwsKmsSlot::GetPublicKeyData() {
    if (this->public_key_data_fetched) {
        return this->public_key_data;
    }

    debug("Getting public key for key %s", this->key_name.c_str());
    Azure::Security::KeyVault::Keys::KeyVaultKey key;
    try {
        key = this->key_client->GetKey(this->key_name).Value;
    } catch (const std::exception& e) {
        debug("Failed to get public key for key %s: %s", this->key_name.c_str(), e.what());
        return {};
    }
    debug("Successfully got public key for key %s", this->key_name.c_str());
    // convert the key to a openssl key
    BIGNUM *n = BN_new();
    BN_bin2bn(key.Key.N.data(), key.Key.N.size(), n);
    BIGNUM *e = BN_new();
    BN_bin2bn(key.Key.E.data(), key.Key.E.size(), e);
    RSA *rsa = RSA_new();
    RSA_set0_key(rsa, n, e, NULL);
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);
    // convert the key to a openssl key
    int len = i2d_PUBKEY(pkey, NULL);
    std::vector<uint8_t> buffer(len);
    unsigned char *ptr = buffer.data();
    i2d_PUBKEY(pkey, &ptr);
    EVP_PKEY_free(pkey);

    this->public_key_data.swap(buffer);
    this->public_key_data_fetched = true;

    return this->public_key_data;
}
