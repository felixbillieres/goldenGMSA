"""
GoldenGMSA Python Package

Équivalence Python de l'outil GoldenGMSA original en C#.
Outil pour exploiter les Group Managed Service Accounts (gMSA) dans Active Directory.

Basé sur la recherche de Yuval Gordon (@YuG0rd).
"""

__version__ = "1.0.0"
__author__ = "GoldenGMSA Python Team"
__description__ = "Outil pour exploiter les Group Managed Service Accounts (gMSA)"

# Imports principaux
from .gmsa_account import GmsaAccount
from .root_key import RootKey
from .gmsa_password import GmsaPassword
from .msds_managed_password_id import MsdsManagedPasswordId
from .ldap_utils import LdapUtils, LdapConnection
from .kds_utils import KdsUtils
from .config import Config

__all__ = [
    'GmsaAccount',
    'RootKey', 
    'GmsaPassword',
    'MsdsManagedPasswordId',
    'LdapUtils',
    'LdapConnection',
    'KdsUtils',
    'Config'
]