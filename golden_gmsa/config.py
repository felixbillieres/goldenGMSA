"""
Configuration pour GoldenGMSA Python.
"""

import os
import logging
from typing import Optional


class Config:
    """
    Classe de configuration pour GoldenGMSA Python.
    """
    
    # Configuration par défaut
    DEFAULT_LDAP_PORT = 389
    DEFAULT_LDAPS_PORT = 636
    DEFAULT_PAGE_SIZE = 100
    DEFAULT_TIMEOUT = 30
    
    # Durée du cycle de clé KDS en nanosecondes (6 minutes)
    KEY_CYCLE_DURATION = 360000000000
    
    # Taille par défaut des données de clé racine KDS
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
    
    # Attributs LDAP requis
    GMSA_REQUIRED_ATTRIBUTES = [
        "msds-ManagedPasswordID",
        "samAccountName", 
        "objectSid",
        "distinguishedName"
    ]
    
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
    
    def __init__(self):
        """Initialise la configuration avec les valeurs par défaut."""
        self.ldap_host: Optional[str] = None
        self.ldap_port: int = self.DEFAULT_LDAP_PORT
        self.ldap_use_ssl: bool = False
        self.ldap_bind_dn: Optional[str] = None
        self.ldap_bind_password: Optional[str] = None
        self.page_size: int = self.DEFAULT_PAGE_SIZE
        self.timeout: int = self.DEFAULT_TIMEOUT
        self.log_level: str = "INFO"
        self.verbose: bool = False
        
        # Charger la configuration depuis les variables d'environnement
        self._load_from_env()
    
    def _load_from_env(self):
        """Charge la configuration depuis les variables d'environnement."""
        self.ldap_host = os.getenv('GOLDEN_GMSA_LDAP_HOST')
        self.ldap_port = int(os.getenv('GOLDEN_GMSA_LDAP_PORT', self.DEFAULT_LDAP_PORT))
        self.ldap_use_ssl = os.getenv('GOLDEN_GMSA_LDAP_SSL', 'false').lower() == 'true'
        self.ldap_bind_dn = os.getenv('GOLDEN_GMSA_LDAP_BIND_DN')
        self.ldap_bind_password = os.getenv('GOLDEN_GMSA_LDAP_BIND_PASSWORD')
        self.page_size = int(os.getenv('GOLDEN_GMSA_PAGE_SIZE', self.DEFAULT_PAGE_SIZE))
        self.timeout = int(os.getenv('GOLDEN_GMSA_TIMEOUT', self.DEFAULT_TIMEOUT))
        self.log_level = os.getenv('GOLDEN_GMSA_LOG_LEVEL', 'INFO')
        self.verbose = os.getenv('GOLDEN_GMSA_VERBOSE', 'false').lower() == 'true'
    
    def get_log_level(self) -> int:
        """Retourne le niveau de log sous forme d'entier."""
        log_levels = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR,
            'CRITICAL': logging.CRITICAL
        }
        return log_levels.get(self.log_level.upper(), logging.INFO)
    
    def to_dict(self) -> dict:
        """Retourne la configuration sous forme de dictionnaire."""
        return {
            'ldap_host': self.ldap_host,
            'ldap_port': self.ldap_port,
            'ldap_use_ssl': self.ldap_use_ssl,
            'ldap_bind_dn': self.ldap_bind_dn,
            'ldap_bind_password': '***' if self.ldap_bind_password else None,
            'page_size': self.page_size,
            'timeout': self.timeout,
            'log_level': self.log_level,
            'verbose': self.verbose
        }
    
    def __str__(self) -> str:
        """Retourne la représentation string de la configuration."""
        config_dict = self.to_dict()
        return f"Config({', '.join(f'{k}={v}' for k, v in config_dict.items())})"
    
    def __repr__(self) -> str:
        """Retourne la représentation officielle de la configuration."""
        return f"Config(ldap_host='{self.ldap_host}', ldap_port={self.ldap_port}, ssl={self.ldap_use_ssl})"


# Instance globale de configuration
config = Config()
