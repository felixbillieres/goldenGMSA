"""
Module pour la gestion des identifiants de mot de passe géré MSDS.
"""

import struct
from typing import Optional
from .ldap_utils import LdapUtils


class MsdsManagedPasswordId:
    """
    Classe représentant un identifiant de mot de passe géré MSDS.
    """
    
    def __init__(self, pwd_blob: bytes):
        """
        Initialise une instance de MsdsManagedPasswordId à partir d'un blob binaire.
        
        Args:
            pwd_blob: Données binaires du blob de mot de passe géré
        """
        self.msds_managed_password_id_bytes = pwd_blob
        
        # Parser le blob binaire
        self.version = struct.unpack('<I', pwd_blob[0:4])[0]
        self.reserved = struct.unpack('<I', pwd_blob[4:8])[0]
        self.is_public_key = struct.unpack('<I', pwd_blob[8:12])[0]
        self.l0_index = struct.unpack('<I', pwd_blob[12:16])[0]
        self.l1_index = struct.unpack('<I', pwd_blob[16:20])[0]
        self.l2_index = struct.unpack('<I', pwd_blob[20:24])[0]
        
        # GUID (16 bytes)
        self.root_key_identifier = str(pwd_blob[24:40])
        
        self.cb_unknown = struct.unpack('<I', pwd_blob[40:44])[0]
        self.cb_domain_name = struct.unpack('<I', pwd_blob[44:48])[0]
        self.cb_forest_name = struct.unpack('<I', pwd_blob[48:52])[0]
        
        # Lire les données inconnues
        if self.cb_unknown > 0:
            self.unknown = pwd_blob[52:52+self.cb_unknown]
        else:
            self.unknown = None
        
        # Lire le nom de domaine
        domain_start = 52 + self.cb_unknown
        self.domain_name = pwd_blob[domain_start:domain_start+self.cb_domain_name].decode('utf-16le')
        
        # Lire le nom de forêt
        forest_start = domain_start + self.cb_domain_name
        self.forest_name = pwd_blob[forest_start:forest_start+self.cb_forest_name].decode('utf-16le')
    
    @staticmethod
    def get_managed_password_id_by_sid(domain_name: str, sid: str) -> Optional['MsdsManagedPasswordId']:
        """
        Récupère l'identifiant de mot de passe géré par SID.
        
        Args:
            domain_name: Nom du domaine
            sid: SID de l'objet
            
        Returns:
            Instance de MsdsManagedPasswordId ou None si non trouvé
        """
        attributes = ["msds-ManagedPasswordID"]
        ldap_filter = f"(objectSID={sid})"
        
        results = LdapUtils.find_in_domain(domain_name, ldap_filter, attributes)
        
        if not results:
            return None
        
        if "msds-ManagedPasswordID" not in results[0]:
            return None
        
        pwd_id_blob = results[0]["msds-ManagedPasswordID"][0]
        return MsdsManagedPasswordId(pwd_id_blob)
    
    def to_string(self) -> str:
        """
        Retourne une représentation string de l'objet.
        
        Returns:
            String formatée contenant les informations
        """
        import base64
        
        result = f"Version: {self.version}\n"
        result += f"Reserved: {self.reserved}\n"
        result += f"Is Public Key: {self.is_public_key}\n"
        result += f"L0 Index: {self.l0_index}\n"
        result += f"L1 Index: {self.l1_index}\n"
        result += f"L2 Index: {self.l2_index}\n"
        result += f"Root Key Identifier: {self.root_key_identifier}\n"
        result += f"Domain Name: {self.domain_name}\n"
        result += f"Forest Name: {self.forest_name}\n"
        result += f"Base64 Blob: {base64.b64encode(self.msds_managed_password_id_bytes).decode('utf-8')}\n"
        
        return result
    
    def __str__(self) -> str:
        """Retourne la représentation string de l'objet."""
        return self.to_string()
    
    def __repr__(self) -> str:
        """Retourne la représentation officielle de l'objet."""
        return f"MsdsManagedPasswordId(root_key_id='{self.root_key_identifier}', domain='{self.domain_name}')"
