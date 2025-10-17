"""
Module pour la gestion des comptes Group Managed Service Account (gMSA).
"""

import logging
from typing import Optional, List, Iterator
from .msds_managed_password_id import MsdsManagedPasswordId
from .ldap_utils import LdapUtils

logger = logging.getLogger(__name__)


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
        pwd_blob = search_result[GmsaAccount.MSDS_MANAGED_PASSWORD_ID_ATTRIBUTE_NAME][0]
        pwd_id = MsdsManagedPasswordId(pwd_blob)
        sid = search_result['objectSid'][0]
        sam_id = search_result['sAMAccountName'][0]
        
        return GmsaAccount(sam_id, dn, sid, pwd_id)
    
    def to_string(self) -> str:
        """
        Retourne une représentation string de l'objet GmsaAccount.
        
        Returns:
            String formatée contenant les informations du gMSA
        """
        import base64
        
        result = f"sAMAccountName:\t\t{self.sam_account_name}\n"
        result += f"objectSid:\t\t\t{self.sid}\n"
        result += f"rootKeyGuid:\t\t{self.managed_password_id.root_key_identifier}\n"
        result += f"msds-ManagedPasswordID:\t{base64.b64encode(self.managed_password_id.msds_managed_password_id_bytes).decode('utf-8')}\n"
        result += "----------------------------------------------\n"
        
        return result
    
    def __str__(self) -> str:
        """Retourne la représentation string de l'objet."""
        return self.to_string()
    
    def __repr__(self) -> str:
        """Retourne la représentation officielle de l'objet."""
        return f"GmsaAccount(sam_account_name='{self.sam_account_name}', sid='{self.sid}')"
