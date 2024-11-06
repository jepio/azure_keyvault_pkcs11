#include "pkcs11-compat.h"
#include "azure-keyvault-slot.h"

CK_RV getKmsKeyAttributeValue(AwsKmsSlot& slot, CK_ATTRIBUTE_TYPE attr, CK_VOID_PTR pValue, CK_ULONG_PTR pulValueLen);
CK_RV getCertificateAttributeValue(AwsKmsSlot& slot, CK_ATTRIBUTE_TYPE attr, CK_VOID_PTR pValue, CK_ULONG_PTR pulValueLen);
