#include <azure/keyvault/keys/key_client.hpp>
#include <azure/identity/environment_credential.hpp>
#include <azure/identity/chained_token_credential.hpp>
#include <azure/identity/managed_identity_credential.hpp>
#include <azure/identity/client_secret_credential.hpp>

#include <openssl/x509.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <string>

#include <json.h>
#include <pkcs11.h>
#include "aws_kms_slot.h"
#include "debug.h"

CK_RV load_config_path(const std::string& path, json_object **config);

static int load_config(json_object** config)
{
    std::vector<string> config_paths;
    config_paths.push_back("/etc/aws-kms-pkcs11/azureauth.json");

    std::string xdg_config_home;
    const char* user_home = getenv("HOME");
    if (user_home != NULL) {
        xdg_config_home = string(user_home) + "/.config";
    }
    if (xdg_config_home.length() > 0) {
        config_paths.push_back(xdg_config_home + "/aws-kms-pkcs11/azureauth.json");
    }
    const char *azure_auth = getenv("AZURE_AUTH_LOCATION");
    if (azure_auth != NULL) {
        config_paths.push_back(azure_auth);
    }

    std::reverse(config_paths.begin(), config_paths.end());

    for (size_t i = 0; i < config_paths.size(); i++) {
        string path = config_paths.at(i);
        if (load_config_path(path, config) == CKR_OK) {
            return 0;
        }
    }

    *config = json_object_new_object();
    return 0;
}

class LazyFileCredential final : public Azure::Core::Credentials::TokenCredential {
public:

    Azure::Core::Credentials::AccessToken GetToken(Azure::Core::Credentials::TokenRequestContext const& tokenRequestContext, Azure::Core::Context const& context) const override
    {
        struct json_object* config = NULL;
        CK_RV res = load_config(&config);
        if (res != CKR_OK) {
            throw Azure::Core::Credentials::AuthenticationException("Failed to load auth file");
        }
        struct json_object* val;
        std::string appId;
        std::string password;
        std::string tenant;
        if (json_object_object_get_ex(config, "appId", &val) && json_object_is_type(val, json_type_string)) {
            appId = string(json_object_get_string(val));
        }
        if (json_object_object_get_ex(config, "password", &val) && json_object_is_type(val, json_type_string)) {
            password = string(json_object_get_string(val));
        }
        if (json_object_object_get_ex(config, "tenant", &val) && json_object_is_type(val, json_type_string)) {
            tenant = string(json_object_get_string(val));
        }
        json_object_put(config);
        return Azure::Identity::ClientSecretCredential(tenant, appId, password).GetToken(tokenRequestContext, context);
    }
};

std::shared_ptr<Azure::Core::Credentials::TokenCredential> get_credential()
{
    static auto chainedTokenCredential = std::make_shared<Azure::Identity::ChainedTokenCredential>(
    Azure::Identity::ChainedTokenCredential::Sources{
        std::make_shared<Azure::Identity::EnvironmentCredential>(),
        std::make_shared<LazyFileCredential>(),
        std::make_shared<Azure::Identity::ManagedIdentityCredential>()});
    return chainedTokenCredential;
}

AwsKmsSlot::AwsKmsSlot(string label, string key_name, string vault_name, X509* certificate) {
    this->label = label;
    this->key_name = key_name;
    this->vault_name = vault_name;
    this->public_key_data_fetched = false;
    this->certificate = certificate;
    this->key_client = std::make_unique<Azure::Security::KeyVault::Keys::KeyClient>(this->vault_name, get_credential());
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
    std::vector<uint8_t> buffer;
    Azure::Security::KeyVault::Keys::KeyVaultKeyType key_type = key.GetKeyType();
    if (key_type == Azure::Security::KeyVault::Keys::KeyVaultKeyType::Rsa) {
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
    } else if (key_type == Azure::Security::KeyVault::Keys::KeyVaultKeyType::Ec) {
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
            debug("Unsupported EC key type %s", key_type.ToString().c_str());
            return {};
        }
        EC_KEY_set_public_key_affine_coordinates(ec, x, y);
        EVP_PKEY *pkey = EVP_PKEY_new();
        EVP_PKEY_assign_EC_KEY(pkey, ec);
        int len = i2d_PUBKEY(pkey, NULL);
        buffer.resize(len);
        unsigned char *ptr = buffer.data();
        i2d_PUBKEY(pkey, &ptr);
        EVP_PKEY_free(pkey);
    } else {
        debug("Key %s is an unknown key type", key_type.ToString().c_str());
        return {};
    }

    this->public_key_data.swap(buffer);
    this->public_key_data_fetched = true;

    return this->public_key_data;
}
