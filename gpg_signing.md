# GPG signing using azure-keyvault-pkcs11

GnuPG can use the PKCS#11 provider by way of [gnupg-pkcs11-scd](https://github.com/alonbl/gnupg-pkcs11-scd). Note that 0.10.0 or later is required.

Configure `gpg-agent` to consult the smartcard daemon. Keys must have corresponding certificates to be discovered by the daemon.

```
mkdir gpgtmp
export GNUPGHOME="${PWD}/gpgtmp"

# configure the agent
cat <<EOF >> "${GNUPGHOME}/gpg-agent.conf"
scdaemon-program /usr/bin/gnupg-pkcs11-scd
EOF

# configure the smartcard daemon
cat <<EOF >> "${GNUPGHOME}/gnupg-pkcs11-scd.conf"
providers kms
provider-kms-library $(pkg-config p11-kit-1 --variable p11_module_path)/azure-keyvault-pkcs11.so
log-file /dev/null
EOF
```

The first import into `gpg` requires the keygrip and additional metadata.

```
# Read keys from the card
gpg --card-status

# Find the keygrip
KEYGRIP=$(find "${GNUPGHOME}"/private-keys-*.d -type f -name '*.key' -printf '%P' | cut -d '.' -f1 | head -n1)

# Import the signing key
# (toggle 'e' since encryption is not supported)
gpg --expert --full-generate-key --command-fd 0 <<EOF
13
${KEYGRIP}
e
q
0
my-signing-key


EOF

# Export the key for subsequent use
gpg --output my-signing-key.gpg my-signing-key
```

Subsequent imports only need the exported key and the smartcard discovery step.

```
gpg --import my-signing-key.gpg
gpg --card-status
```
