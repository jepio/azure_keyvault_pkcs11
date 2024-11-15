# azure-keyvault-pkcs11

This repository contains a PKCS#11 implementation that uses [Microsoft Azure Key Vault](https://azure.microsoft.com/products/key-vault) as its backend. This allows you to bridge software that requires PKCS#11 plugins (like code signing or certificate management software) with Key Vault for key storage and management.

This implementation is not meant to be complete; it only implements enough of the PKCS#11 interface to enable signing with keys previously created in Key Vault. Functionality such as creating new keys is not supported.

# Keys or certificates?

Azure Key Vault can host bare private keys or certificates with associated private keys. This module can be used with either, but if a bare private key is used and the operation expects the PKCS#11 token to have a certificate, then an associated certificate must be provided in the configuration file.

# Authentication

This module supports the following authentication methods:

* [Environment variables](https://learn.microsoft.com/dotnet/api/azure.identity.environmentcredential)
* Credentials stored in:
  * The file referenced by the `AZURE_AUTH_LOCATION` environment variable
  * `${XDG_CONFIG_HOME}/azure-keyvault-pkcs11/azureauth.json` (where `XDG_CONFIG_HOME` defaults to `~/.config`)
  * `/etc/azure-keyvault-pkcs11/azureauth.json`
* [Azure CLI](https://learn.microsoft.com/cli/azure/) aka `az` (must be installed and in the PATH)
* [Managed identity](https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/)

These methods are tried in the above order. The credentials file takes the following form:

```json
{
  "tenant": "4b635cd9-c799-491b-9c38-9b57f19c82f8",
  "appId": "4a4bd003-9277-43a9-ba64-31d004c9b242",
  "password": "supersecret"
}
```

# Examples

## PKCS#11 URIs

This module exposes Key Vault keys under a single token and slot. You can configure the module to expose all your Key Vault keys, a select few, or even just one; see the configuration section below. If you are exposing more than one key, and your PKCS#11 consumer supports it, you can use PKCS#11 URIs to specify the key that you want to use. For example:

```
export PKCS11_MODULE_PATH=$(pkg-config p11-kit-1 --variable p11_module_path)/azure-keyvault-pkcs11.so
openssl pkeyutl -engine pkcs11 -sign -inkey pkcs11:token=my-signing-key -keyform engine -out foo.sig -in foo
```

The token label used in the URI should match the label used in the configuration (see below). If you have not provided a configuration or specified a label, then the first 32 characters of the key's name will be used as the label.

## Use with libp11 (aka libengine-pkcs11-openssl)

Note that this PKCS#11 provider allows for use of private keys without a "PIN". Previous versions of libp11 [did not allow](https://github.com/OpenSC/libp11/issues/242) the use of such keys. In particular, this version of libp11 is present in version of Ubuntu before focal, so make sure you are using libp11 >= 0.4.10.

You can do some simple verification of this module with the pkcs11 engine by following this example:

```
AZURE_KEYVAULT_PKCS11_DEBUG=1 openssl
OpenSSL> engine pkcs11 -pre VERBOSE -pre MODULE_PATH:/usr/lib/x86_64-linux-gnu/pkcs11/azure-keyvault-pkcs11.so
(pkcs11) pkcs11 engine
[Success]: VERBOSE
[Success]: MODULE_PATH:/usr/lib/x86_64-linux-gnu/pkcs11/azure-keyvault-pkcs11.so
OpenSSL>
OpenSSL> pkeyutl -engine pkcs11 -sign -inkey pkcs11:token=my-signing-key -keyform engine -out foo.sig -in foo
Engine "pkcs11" set.
AZURE_KEYVAULT: Debug enabled.
AZURE_KEYVAULT: Attempting to load config from path: ~/.config/azure-keyvault-pkcs11/config.json
AZURE_KEYVAULT: Parsing certificate for slot: my-signing-key
AZURE_KEYVAULT: Attempting to load config from path: ~/.config/azure-keyvault-pkcs11/azureauth.json
AZURE_KEYVAULT: Skipping config because we couldn't open the file.
AZURE_KEYVAULT: Attempting to load config from path: /etc/azure-keyvault-pkcs11/azureauth.json
AZURE_KEYVAULT: Skipping config because we couldn't open the file.
AZURE_KEYVAULT: Configured slots:
AZURE_KEYVAULT:   my-remote-key-name
AZURE_KEYVAULT: Getting public key for key my-remote-key-name
AZURE_KEYVAULT: Successfully got public key for key my-remote-key-name
AZURE_KEYVAULT: Key my-remote-key-name is an RSA key
AZURE_KEYVAULT: Successfully called Key Vault to do a signing operation.

```

If you have downloaded the public key from Key Vault to `my-signing-key.pub` you can verify the above signature with

```
openssl pkeyutl -in foo -verify -sigfile foo.sig -inkey my-signing-key.pub  -pubin
Signature Verified Successfully
```

This example using `pkeyutl` assumes you are using an EC key.
If you are using an RSA key, append the `-pkeyopt digest:sha256` option to both the sign and verify steps.

## Generate a self-signed certificate

This will create a self-signed certificate in `mycert.pem` using your Key Vault key.

```
$ CONFIG="
[req]
distinguished_name=dn
[ dn ]
"

$ PKCS11_MODULE_PATH=$(pkg-config p11-kit-1 --variable p11_module_path)/azure-keyvault-pkcs11.so openssl req -config <(echo "$CONFIG") -x509 -key pkcs11:token=my-signing-key -keyform engine -engine pkcs11 -out mycert.pem -subj '/CN=mycert' -days 366 -addext basicConstraints=critical,CA:FALSE
```

## Windows code signing

Using [osslsigncode](https://github.com/mtrojnar/osslsigncode):

```
osslsigncode sign -h sha256 \
    -pkcs11engine /usr/lib/x86_64-linux-gnu/engines-1.1/pkcs11.so \
    -pkcs11module $(pkg-config p11-kit-1 --variable p11_module_path)/azure-keyvault-pkcs11.so \
    -certs mycert.pem -key 'pkcs11:token=my-signing-key' -in ~/foo.exe -out ~/foo-signed.exe
```

## Signing RAUC bundles

Since [RAUC](https://github.com/rauc/rauc) supports PKCS#11 keys, you can use your Key Vault key to sign RAUC bundles.

```
RAUC_PKCS11_MODULE=$(pkg-config p11-kit-1 --variable p11_module_path)/azure-keyvault-pkcs11.so rauc bundle --cert=mycert.pem --key='pkcs11:token=my-signing-key' input_dir/ my_bundle.raucb
```

## SSH

I'm not really sure why you'd want to do this, but you can!

```
~$ ssh-add -s "$(pkg-config p11-kit-1 --variable p11_module_path)"/azure-keyvault-pkcs11.so
Enter passphrase for PKCS#11: # Just press enter; no password is used
Card added: /usr/lib/x86_64-linux-gnu/pkcs11/azure-keyvault-pkcs11.so
~$ ssh-add -L
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLJqRBbRtYDvgNjK5xK1IcBaahVzbOyZULDjNpQ4VrWfmwthtIm4VEQLINherX8qx2hLaabvUfr7WLC5LDuyX6Q= dbafb7de-106e-4277-97fe-a7f5635516a5
~$ ssh-add -L >> ~/.ssh/authorized_keys
~$ ssh localhost
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-65-generic x86_64)

Last login: Thu Nov 19 10:35:42 2020
~$
```

## p11tool Configuration

p11tool is a useful tool included as part of [GnuTLS](https://www.gnutls.org). Once installed, you can configure it to be aware of the azure-keyvault-pkcs11 module as follows:

```
sudo mkdir -p /etc/pkcs11/modules
sudo touch /etc/pkcs11/pkcs11.conf
sudo tee /etc/pkcs11/modules/azure-keyvault-pkcs11.module <<EOF
module: $(pkg-config p11-kit-1 --variable p11_module_path)/azure-keyvault-pkcs11.so
critical: no
EOF
```

Once configured, you can use the `p11tool` command to show some helpful information.

```
p11tool --list-tokens
p11tool --list-token-urls
```

## Kernel Module Signing

An example of kernel module signing [can be found here](kernel_mod_signing.md).

## GPG Signing

An example of GPG signing [can be found here](gpg_signing.md).

## pesign

pesign is used by most Linux distributions to sign PE binaries for Secure Boot.

It uses the NSS libraries, which rely on a "certdb" database with the certificates, and the configuration of the PKCS11 modules. In this example, we'll create a custom certdb for signing, and add our module to it:

```
mkdir my-cert-db
certutil -N --empty-password -d my-cert-db
modutil -dbdir my-cert-db -add kms -libfile $(pkg-config p11-kit-1 --variable p11_module_path)/azure-keyvault-pkcs11.so
```

You can check that the key and certificate are there:
```
certutil -d my-cert-db -K -h all
certutil -d my-cert-db -L -h all
```

Now, assuming you have a key names "my-signing-key" configured with a certificate setup in your JSON file (as documented below), you can do:

```
pesign -i <input_file> -o <output_file> -s -n my-cert-db -c my-signing-key -t my-signing-key
```


# Configuration

If no configuration is provided, you must set the Key Vault URL using the `AZURE_KEYVAULT_URL` environment variable. The module will then list all keys in that Key Vault and make them available as "tokens" in the provider. The label on each token will be the first 32 characters of the key's name.

The configuration file is loaded from either:

* `${XDG_CONFIG_HOME}/azure-keyvault-pkcs11/config.json` (where `XDG_CONFIG_HOME` defaults to `~/.config`)
* `/etc/azure-keyvault-pkcs11/config.json`

The following is an example configuration file:

```json
{
  "slots": [
    {
      "label": "my-signing-key",
      "key_name": "my-remote-key-name",
      "vault_url": "https://my-vault.vault.azure.net/",
      "certificate_path": "/etc/azure-keyvault-pkcs11/cert.pem"
    }
  ]
}
```

The `slots` key is the only supported top-level attribute at the moment. This is a list of slot objects. The following keys are supported on each slot:

| Key               | Required | Example                               | Explanation |
| ----------------- | -------- | ------------------------------------- | ----------- |
| key\_name         | Y        | my-remote-key-name                    | The key's name as shown by Azure. |
| label             | N        | my-signing-key                        | The token label. This is normally referenced by a PKCS#11 URI. If not specified, the first 32 characters of the key's name will be used. |
| vault\_url        | N        | https://my-vault.vault.azure.net/     | The vault URI as shown by Azure. This should always end with `.vault.azure.net/`. |
| certificate       | N        | MIIDQjCCAiqgAwIBAgIQdSf9vqq4SRao0/... | A base64-encoded DER-encoded X.509 certificate to expose as an object on this slot. Useful in cases where an operation expects the PKCS#11 token to have a certificate. Render a certificate in this format with: `openssl x509 -in mycert.pem -outform der \| openssl base64 -A` |
| certificate\_path | N        | /etc/azure-keyvault-pkcs11/mycert.pem | Same as `certificate` but references a PEM certificate on disk instead of embedding the certificate data into the config. |

If you are encountering errors using this provider, try setting the `AZURE_KEYVAULT_PKCS11_DEBUG` environment variable to a non-empty value. This will enable debug logging to stderr from the module.

# Building from source

## Requirements

All the following, bar Azure SDK for C++, are almost certainly available as packages in your distribution.

### Tools

* [CMake](https://cmake.org)
* [pkgconf](http://pkgconf.org) or [pkg-config](https://www.freedesktop.org/wiki/Software/pkg-config/)

### Libraries (including development headers)

* [OpenSSL](https://openssl-library.org)
* [JSON-C](https://github.com/json-c/json-c/wiki)
* [Azure SDK for C++](https://azure.github.io/azure-sdk-for-cpp/)

## Process

From a clone of the git repository or the extracted tarball:

```
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=/usr
cmake --build build
sudo cmake --install build
```
