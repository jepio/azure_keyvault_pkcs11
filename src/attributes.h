#include "pkcs11-compat.h"
#include "azure-keyvault-slot.h"

CK_RV getKeyVaultKeyAttributeValue(AzureKeyVaultSlot& slot, CK_ATTRIBUTE_TYPE attr, CK_VOID_PTR pValue, CK_ULONG_PTR pulValueLen);
CK_RV getCertificateAttributeValue(AzureKeyVaultSlot& slot, CK_ATTRIBUTE_TYPE attr, CK_VOID_PTR pValue, CK_ULONG_PTR pulValueLen);
