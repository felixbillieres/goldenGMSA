"""
Constantes pour GoldenGMSA Python.
Module centralisé pour toutes les constantes du projet.
"""

# Durée du cycle de clé KDS en nanosecondes (6 minutes = 360 secondes)
KEY_CYCLE_DURATION = 360000000000

# Taille par défaut des données de clé racine KDS (en bytes)
KDS_ROOT_KEY_DATA_SIZE_DEFAULT = 64

# Descripteur de sécurité GMSA par défaut
DEFAULT_GMSA_SECURITY_DESCRIPTOR = bytes([
    0x01, 0x00, 0x04, 0x80, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x14, 0x00, 0x00, 0x00, 0x02, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0x00, 0x9F, 0x01, 0x12, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x09,
    0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00
])

# Filtres LDAP par défaut
GMSA_LDAP_FILTER = "(objectCategory=msDS-GroupManagedServiceAccount)"
KDS_ROOT_KEY_LDAP_FILTER = "(objectClass=msKds-ProvRootKey)"

# Attributs LDAP requis pour les gMSA
GMSA_REQUIRED_ATTRIBUTES = [
    "msds-ManagedPasswordID",
    "samAccountName",
    "objectSid",
    "distinguishedName"
]

# Attributs LDAP requis pour les clés racine KDS
KDS_ROOT_KEY_REQUIRED_ATTRIBUTES = [
    "msKds-SecretAgreementParam",
    "msKds-RootKeyData",
    "msKds-KDFParam",
    "msKds-KDFAlgorithmID",
    "msKds-CreateTime",
    "msKds-UseStartTime",
    "msKds-Version",
    "msKds-DomainID",
    "cn",
    "msKds-PrivateKeyLength",
    "msKds-PublicKeyLength",
    "msKds-SecretAgreementAlgorithmID"
]

# Configuration LDAP
LDAP_PORT = 389
LDAPS_PORT = 636
LDAP_PAGE_SIZE = 100
LDAP_TIMEOUT = 10
