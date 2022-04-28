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

AwsKmsSlot::AwsKmsSlot(const string &label, const string &key_name, const string &vault_name,
                       const X509* certificate) :
    label(label), key_name(key_name), vault_name(vault_name),
    certificate(certificate),
    public_key_data_fetched(false)
{
    auto credential = std::make_shared<Azure::Identity::EnvironmentCredential>();
    this->key_client = std::make_unique<Azure::Security::KeyVault::Keys::KeyClient>(this->vault_name, credential);
}

const string &AwsKmsSlot::GetLabel() {
    return this->label;
}
const string & AwsKmsSlot::GetVaultName() {
    return this->vault_name;
}
const string & AwsKmsSlot::GetKeyName() {
    return this->key_name;
}
const X509* AwsKmsSlot::GetCertificate() {
    return this->certificate;
}
Azure::Security::KeyVault::Keys::Cryptography::CryptographyClient AwsKmsSlot::GetCryptoClient() {
    return this->key_client->GetCryptographyClient(this->key_name);
}
void AwsKmsSlot::FetchPublicKeyData() {
    if (this->public_key_data_fetched) {
        return;
    }

    debug("Getting public key for key %s", this->key_name.c_str());
    Azure::Security::KeyVault::Keys::KeyVaultKey key;
    try {
        key = this->key_client->GetKey(this->key_name).Value;
    } catch (const std::exception& e) {
        debug("Failed to get public key for key %s: %s", this->key_name.c_str(), e.what());
        return;
    }
    debug("Successfully got public key for key %s", this->key_name.c_str());
    std::vector<uint8_t> buffer;
    if (key.Key.KeyType == Azure::Security::KeyVault::Keys::KeyVaultKeyType::Rsa ||
        key.Key.KeyType == Azure::Security::KeyVault::Keys::KeyVaultKeyType::RsaHsm) {
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
        buffer.resize(len);
        unsigned char *ptr = buffer.data();
        i2d_PUBKEY(pkey, &ptr);
        EVP_PKEY_free(pkey);
        this->key_size = key.Key.N.size() * 8;
    } else {
        debug("Key %s is an unknown key type", key.Key.KeyType.ToString().c_str());
        return;
    }

    this->public_key_data.swap(buffer);
    this->public_key_data_fetched = true;
}
std::vector<uint8_t> AwsKmsSlot::GetPublicKeyData() {
    this->FetchPublicKeyData();
    return this->public_key_data;
}
const unsigned int AwsKmsSlot::GetKeySize() {
    this->FetchPublicKeyData();
    return this->key_size;
}
