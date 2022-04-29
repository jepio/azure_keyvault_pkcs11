#include <azure/keyvault/keys/key_client.hpp>
#include <azure/identity/environment_credential.hpp>
#include <azure/identity/managed_identity_credential.hpp>
#include <azure/identity/chained_token_credential.hpp>

#include <openssl/x509.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <string>

#include "aws_kms_slot.h"
#include "debug.h"

using std::string;

std::shared_ptr<Azure::Core::Credentials::TokenCredential> get_credential()
{
    static auto chainedTokenCredential = std::make_shared<Azure::Identity::ChainedTokenCredential>(
    Azure::Identity::ChainedTokenCredential::Sources{
        std::make_shared<Azure::Identity::EnvironmentCredential>(),
        std::make_shared<Azure::Identity::ManagedIdentityCredential>()});
    return chainedTokenCredential;
}

AwsKmsSlot::AwsKmsSlot(const string &label, const string &key_name, const string &vault_name,
                       const X509* certificate) :
    label(label), key_name(key_name), vault_name(vault_name),
    certificate(certificate),
    public_key_data_fetched(false)
{
    this->key_client = std::make_unique<Azure::Security::KeyVault::Keys::KeyClient>(this->vault_name, get_credential());
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
        debug("Key %s is an RSA key", this->key_name.c_str());
        // convert the key to a openssl key
        BIGNUM *n = BN_new();
        BN_bin2bn(key.Key.N.data(), key.Key.N.size(), n);
        BIGNUM *e = BN_new();
        BN_bin2bn(key.Key.E.data(), key.Key.E.size(), e);
        RSA *rsa = RSA_new();
        RSA_set0_key(rsa, n, e, NULL);
        EVP_PKEY *pkey = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(pkey, rsa);
        int len = i2d_PUBKEY(pkey, NULL);
        buffer.resize(len);
        unsigned char *ptr = buffer.data();
        i2d_PUBKEY(pkey, &ptr);
        EVP_PKEY_free(pkey);
        this->key_size = key.Key.N.size() * 8;
    } else if (key.Key.KeyType == Azure::Security::KeyVault::Keys::KeyVaultKeyType::Ec ||
               key.Key.KeyType == Azure::Security::KeyVault::Keys::KeyVaultKeyType::EcHsm) {
        debug("Key %s is an EC key", this->key_name.c_str());
        // convert the key to a openssl key
        BIGNUM *x = BN_new();
        BN_bin2bn(key.Key.X.data(), key.Key.X.size(), x);
        BIGNUM *y = BN_new();
        BN_bin2bn(key.Key.Y.data(), key.Key.Y.size(), y);
        EC_KEY *ec = nullptr;
        Azure::Security::KeyVault::Keys::KeyCurveName curve_name = key.Key.CurveName.ValueOr({});
        if (curve_name == curve_name.P256) {
            ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        } else if (curve_name == curve_name.P384) {
            ec = EC_KEY_new_by_curve_name(NID_secp384r1);
        } else if (curve_name == curve_name.P521) {
            ec = EC_KEY_new_by_curve_name(NID_secp521r1);
        } else {
            debug("Unsupported EC key type %s", key.Key.KeyType.ToString().c_str());
            return;
        }
        EC_KEY_set_public_key_affine_coordinates(ec, x, y);
        EVP_PKEY *pkey = EVP_PKEY_new();
        EVP_PKEY_assign_EC_KEY(pkey, ec);
        this->key_size = EVP_PKEY_bits(pkey);
        int len = i2d_PUBKEY(pkey, NULL);
        buffer.resize(len);
        unsigned char *ptr = buffer.data();
        i2d_PUBKEY(pkey, &ptr);
        EVP_PKEY_free(pkey);
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
