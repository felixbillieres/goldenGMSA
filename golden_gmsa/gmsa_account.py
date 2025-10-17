"""
Module pour la gestion des comptes Group Managed Service Account (gMSA).
"""

import logging
import struct
from typing import Optional, List, Iterator
from .msds_managed_password_id import MsdsManagedPasswordId
from .ldap_utils import LdapUtils

logger = logging.getLogger(__name__)


def convert_sid_to_string(sid_bytes: bytes) -> str:
    """
    Convertit un SID en bytes vers sa représentation string.
    
    Args:
        sid_bytes: SID au format bytes
        
    Returns:
        SID au format string (ex: S-1-5-21-...)
    """
    if not sid_bytes or len(sid_bytes) < 8:
        return str(sid_bytes)
    
    try:
        # Structure du SID:
        # byte 0: Revision (toujours 1)
        # byte 1: Nombre de sous-autorités
        # bytes 2-7: Autorité (6 bytes, big-endian)
        # bytes 8+: Sous-autorités (4 bytes chacune, little-endian)
        
        revision = sid_bytes[0]
        sub_auth_count = sid_bytes[1]
        
        # Autorité (6 bytes en big-endian, mais on utilise 8 bytes avec padding)
        authority = struct.unpack('>Q', b'\x00\x00' + sid_bytes[2:8])[0]
        
        # Construction du SID
        sid = f'S-{revision}-{authority}'
        
        # Ajout des sous-autorités
        for i in range(sub_auth_count):
            offset = 8 + (i * 4)
            if offset + 4 <= len(sid_bytes):
                sub_auth = struct.unpack('<I', sid_bytes[offset:offset + 4])[0]
                sid += f'-{sub_auth}'
        
        return sid
    except Exception as e:
        logger.warning(f"Erreur lors de la conversion du SID: {e}")
        return str(sid_bytes)


class GmsaAccount:
    """
    Classe représentant un compte Group Managed Service Account (gMSA).
    """
    
    # Attributs LDAP requis pour les gMSA
    GMSA_REQUIRED_LDAP_ATTRIBUTES = [
        "msDS-ManagedPasswordId",
        "sAMAccountName", 
        "objectSid",
        "distinguishedName"
    ]
    
    MSDS_MANAGED_PASSWORD_ID_ATTRIBUTE_NAME = "msDS-ManagedPasswordId"
    IS_GMSA_ACCOUNT_LDAP_FILTER = "(objectCategory=msDS-GroupManagedServiceAccount)"
    
    def __init__(self, sam_account_name: str, dn: str, sid: str, pwd_id: MsdsManagedPasswordId):
        """
        Initialise une instance de GmsaAccount.
        
        Args:
            sam_account_name: Nom du compte SAM
            dn: Nom distinctif (Distinguished Name)
            sid: Identifiant de sécurité (SID)
            pwd_id: Identifiant de mot de passe géré
        """
        self.distinguished_name = dn
        self.managed_password_id = pwd_id
        self.sid = sid
        self.sam_account_name = sam_account_name
    
    @staticmethod
    def get_gmsa_account_by_sid(domain_fqdn: str, sid: str) -> Optional['GmsaAccount']:
        """
        Retourne les informations du compte gMSA à partir de son SID.
        
        Args:
            domain_fqdn: FQDN du domaine à rechercher
            sid: Le SID du gMSA
            
        Returns:
            Instance de GmsaAccount ou None si non trouvé
        """
        if not sid:
            raise ValueError("Le paramètre sid ne peut pas être None")
        
        if not domain_fqdn:
            raise ValueError("Le paramètre domain_fqdn ne peut pas être None")
        
        ldap_filter = f"(&{GmsaAccount.IS_GMSA_ACCOUNT_LDAP_FILTER}(objectsid={sid}))"
        results = LdapUtils.find_in_domain(domain_fqdn, ldap_filter, GmsaAccount.GMSA_REQUIRED_LDAP_ATTRIBUTES)
        
        if not results:
            return None
        
        return GmsaAccount._get_gmsa_from_search_result(results[0])
    
    @staticmethod
    def find_all_gmsa_accounts_in_domain(domain_fqdn: str) -> Iterator['GmsaAccount']:
        """
        Retourne tous les comptes gMSA dans le domaine.
        
        Args:
            domain_fqdn: FQDN du domaine à rechercher
            
        Yields:
            Instances de GmsaAccount
        """
        if not domain_fqdn:
            raise ValueError("Le paramètre domain_fqdn ne peut pas être vide")
        
        results = LdapUtils.find_in_domain(
            domain_fqdn, 
            GmsaAccount.IS_GMSA_ACCOUNT_LDAP_FILTER, 
            GmsaAccount.GMSA_REQUIRED_LDAP_ATTRIBUTES
        )
        
        if not results:
            return
        
        for result in results:
            gmsa = None
            try:
                gmsa = GmsaAccount._get_gmsa_from_search_result(result)
            except Exception as ex:
                dn = result.get('distinguishedName', ['Inconnu'])[0]
                logger.warning(f"{dn}: {ex}")
            
            if gmsa:
                yield gmsa
    
    @staticmethod
    def _get_gmsa_from_search_result(search_result: dict) -> 'GmsaAccount':
        """
        Crée une instance GmsaAccount à partir d'un résultat de recherche LDAP.
        
        Args:
            search_result: Résultat de recherche LDAP
            
        Returns:
            Instance de GmsaAccount
            
        Raises:
            KeyError: Si un attribut requis est manquant
        """
        if not search_result:
            raise ValueError("Le paramètre search_result ne peut pas être None")
        
        # Vérifier que tous les attributs requis sont présents
        for attr in GmsaAccount.GMSA_REQUIRED_LDAP_ATTRIBUTES:
            if attr not in search_result:
                raise KeyError(f"L'attribut {attr} n'a pas été trouvé")
        
        dn = search_result['distinguishedName'][0]
        if isinstance(dn, bytes):
            dn = dn.decode('utf-8')
            
        pwd_blob = search_result[GmsaAccount.MSDS_MANAGED_PASSWORD_ID_ATTRIBUTE_NAME][0]
        pwd_id = MsdsManagedPasswordId(pwd_blob)
        
        sid_bytes = search_result['objectSid'][0]
        sid = convert_sid_to_string(sid_bytes)
        
        sam_id = search_result['sAMAccountName'][0]
        if isinstance(sam_id, bytes):
            sam_id = sam_id.decode('utf-8')
        
        return GmsaAccount(sam_id, dn, sid, pwd_id)
    
    def to_string(self) -> str:
        """
        Retourne une représentation string de l'objet GmsaAccount.
        
        Returns:
            String formatée contenant les informations du gMSA
        """
        import base64
        
        result = f"sAMAccountName:         {self.sam_account_name}\n"
        result += f"objectSid:              {self.sid}\n"
        result += f"distinguishedName:      {self.distinguished_name}\n"
        result += f"rootKeyGuid:            {self.managed_password_id.root_key_identifier}\n"
        result += f"domainName:             {self.managed_password_id.domain_name}\n"
        result += f"forestName:             {self.managed_password_id.forest_name}\n"
        result += f"L0 Index:               {self.managed_password_id.l0_index}\n"
        result += f"L1 Index:               {self.managed_password_id.l1_index}\n"
        result += f"L2 Index:               {self.managed_password_id.l2_index}\n"
        result += f"msDS-ManagedPasswordId: {base64.b64encode(self.managed_password_id.msds_managed_password_id_bytes).decode('utf-8')}\n"
        result += "----------------------------------------------\n"
        
        return result
    
    def __str__(self) -> str:
        """Retourne la représentation string de l'objet."""
        return self.to_string()
    
    def __repr__(self) -> str:
        """Retourne la représentation officielle de l'objet."""
        return f"GmsaAccount(sam_account_name='{self.sam_account_name}', sid='{self.sid}')"
