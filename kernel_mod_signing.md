# Signing kernel modules using azure-keyvault-pkcs11

When building a custom kernel, it may be useful to sign the modules to prevent unauthorized module loading on the system. This is most appropriate for embedded devices. The process is pretty straightforward.

At first, we need to do a fake build to get a x509.genkey file that we can use for generating the certificate. A sample is included, but it's better to use the same one the kernel would use. The kernel will automatically generate this file and create a certificate if `CONFIG_MODULE_SIG_KEY=""`, so we take advantage of this to get a sample x509.genkey file.

Add the following to the kernel config:

```ini
CONFIG_MODULE_SIG=y
CONFIG_MODULE_SIG_SHA256=y
CONFIG_MODULE_SIG_KEY=""
```

Then build the kernel using `make` and the x509.genkey file should be located in `<kernel_source>/certs/x509.genkey`. You will use this file to self-sign a certificate in the following step.

If you want to skip the above step and use a passed file, here is a sample. Some extra fields have been added (such as Organisation Name) to provide extra information in the certificate.

```ini
[ req ]
default_bits = 2048
distinguished_name = req_distinguished_name
prompt = no
string_mask = utf8only
x509_extensions = myexts

[ req_distinguished_name ]
countryName            = US
stateOrProvinceName    = Your State
localityName           = Your City
organizationName       = Your Company
commonName             = Kernel Signing Key
emailAddress           = you@example.com

[ myexts ]
basicConstraints=critical,CA:FALSE
keyUsage=digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
```

Add a slot for your key to the azure-keyvault-pkcs11 configuration, then sign your certificate with the following:

```
PKCS11_MODULE_PATH=$(pkg-config p11-kit-1 --variable p11_module_path)/azure-keyvault-pkcs11.so openssl req -config <(< "<kernel_source>"/certs/x509.genkey) -x509 -key "pkcs11:token=<your_key_label>" -keyform engine -engine pkcs11 -out mycert.pem -days 36500
```

Now that you have a signed certificate, add it to the slot's configuration with this line:

```json
"certificate_path": "mycert.pem"
```

Update your kernel config:

```ini
CONFIG_MODULE_SIG_KEY="pkcs11:token=<your_key_label>"
```

Now build the kernel as normal and modules will be signed using Key Vault and the certificate you just signed above.

Make sure to keep the self-signed certificate in a safe place.
