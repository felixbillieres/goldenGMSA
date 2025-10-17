"""
Utilitaires pour les opérations LDAP avec Active Directory.
"""

import logging
import socket
from typing import List, Optional, Dict, Any
import ldap
import ldap.filter

logger = logging.getLogger(__name__)


class LdapUtils:
    """
    Classe utilitaire pour les opérations LDAP avec Active Directory.
    """
    
    @staticmethod
    def find_in_config_partition(domain_fqdn: str, ldap_filter: str, attributes: List[str]) -> List[Dict[str, Any]]:
        """
        Recherche dans la partition de configuration.
        
        Args:
            domain_fqdn: FQDN du domaine
            ldap_filter: Filtre LDAP
            attributes: Liste des attributs à récupérer
            
        Returns:
            Liste des résultats de recherche
            
        Raises:
            Exception: Si la recherche échoue
        """
        config_naming_context = LdapUtils._get_config_naming_context(domain_fqdn)
        return LdapUtils._perform_ldap_search(domain_fqdn, config_naming_context, ldap_filter, attributes)
    
    @staticmethod
    def find_in_domain(domain_fqdn: str, ldap_filter: str, attributes: List[str]) -> List[Dict[str, Any]]:
        """
        Recherche dans le domaine.
        
        Args:
            domain_fqdn: FQDN du domaine
            ldap_filter: Filtre LDAP
            attributes: Liste des attributs à récupérer
            
        Returns:
            Liste des résultats de recherche
            
        Raises:
            Exception: Si la recherche échoue
        """
        default_naming_context = LdapUtils._get_default_naming_context(domain_fqdn)
        return LdapUtils._perform_ldap_search(domain_fqdn, default_naming_context, ldap_filter, attributes)
    
    @staticmethod
    def get_root_dse(domain_fqdn: str) -> Dict[str, Any]:
        """
        Récupère les informations RootDSE.
        
        Args:
            domain_fqdn: FQDN du domaine
            
        Returns:
            Dictionnaire contenant les informations RootDSE
        """
        try:
            # Échapper le nom de domaine pour LDAP
            domain_escaped = ldap.filter.escape_filter_chars(domain_fqdn)
            server_uri = f"ldap://{domain_escaped}"
            
            # Connexion anonyme pour récupérer RootDSE
            conn = ldap.initialize(server_uri)
            conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
            conn.set_option(ldap.OPT_REFERRALS, 0)
            
            # Recherche RootDSE
            result = conn.search_s("", ldap.SCOPE_BASE, "(objectClass=*)")
            conn.unbind()
            
            if result and len(result) > 0:
                return result[0][1]  # Retourner les attributs
            else:
                raise Exception("Impossible de récupérer les informations RootDSE")
                
        except Exception as ex:
            logger.error(f"Erreur lors de la récupération RootDSE pour {domain_fqdn}: {ex}")
            raise
    
    @staticmethod
    def get_current_domain() -> str:
        """
        Détermine le domaine actuel en utilisant les informations système.
        
        Returns:
            Nom du domaine actuel
        """
        try:
            # Essayer de récupérer le domaine via le nom d'hôte
            hostname = socket.getfqdn()
            if '.' in hostname:
                return hostname.split('.', 1)[1]
            
            # Fallback: utiliser le nom d'hôte tel quel
            return hostname
            
        except Exception as ex:
            logger.warning(f"Impossible de déterminer le domaine actuel: {ex}")
            return "localhost"
    
    @staticmethod
    def get_current_forest() -> str:
        """
        Détermine la forêt actuelle (pour l'instant, utilise le domaine actuel).
        
        Returns:
            Nom de la forêt actuelle
        """
        return LdapUtils.get_current_domain()
    
    @staticmethod
    def _get_default_naming_context(domain_name: str) -> str:
        """
        Récupère le contexte de dénomination par défaut.
        
        Args:
            domain_name: Nom du domaine
            
        Returns:
            Contexte de dénomination par défaut
        """
        root_dse = LdapUtils.get_root_dse(domain_name)
        return root_dse.get('defaultNamingContext', [b''])[0].decode('utf-8')
    
    @staticmethod
    def _get_config_naming_context(domain_name: str) -> str:
        """
        Récupère le contexte de dénomination de configuration.
        
        Args:
            domain_name: Nom du domaine
            
        Returns:
            Contexte de dénomination de configuration
        """
        root_dse = LdapUtils.get_root_dse(domain_name)
        return root_dse.get('configurationNamingContext', [b''])[0].decode('utf-8')
    
    @staticmethod
    def _perform_ldap_search(domain_fqdn: str, search_base: str, ldap_filter: str, attributes: List[str]) -> List[Dict[str, Any]]:
        """
        Effectue une recherche LDAP.
        
        Args:
            domain_fqdn: FQDN du domaine
            search_base: Base de recherche
            ldap_filter: Filtre LDAP
            attributes: Liste des attributs à récupérer
            
        Returns:
            Liste des résultats de recherche
            
        Raises:
            Exception: Si la recherche échoue
        """
        try:
            # Échapper le nom de domaine pour LDAP
            domain_escaped = ldap.filter.escape_filter_chars(domain_fqdn)
            server_uri = f"ldap://{domain_escaped}"
            
            # Connexion LDAP
            conn = ldap.initialize(server_uri)
            conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
            conn.set_option(ldap.OPT_REFERRALS, 0)
            
            # Recherche avec pagination
            results = []
            page_size = 100
            
            # Utiliser SimplePagedResultsControl pour la pagination
            page_control = ldap.controls.SimplePagedResultsControl(True, size=page_size, cookie='')
            
            while True:
                try:
                    # Effectuer la recherche
                    msgid = conn.search_ext(
                        search_base,
                        ldap.SCOPE_SUBTREE,
                        ldap_filter,
                        attributes,
                        serverctrls=[page_control]
                    )
                    
                    # Récupérer les résultats
                    result_type, result_data, result_msgid, result_controls = conn.result3(msgid)
                    
                    # Traiter les résultats
                    for dn, attrs in result_data:
                        if dn:  # Ignorer les entrées vides
                            results.append(attrs)
                    
                    # Vérifier s'il y a plus de résultats
                    page_control = None
                    for control in result_controls:
                        if control.controlType == ldap.controls.SimplePagedResultsControl.controlType:
                            page_control = control
                            break
                    
                    if not page_control or not page_control.cookie:
                        break
                        
                except ldap.SIZELIMIT_EXCEEDED:
                    # Limite de taille atteinte, continuer avec les résultats obtenus
                    logger.warning("Limite de taille LDAP atteinte")
                    break
                except Exception as ex:
                    logger.error(f"Erreur lors de la recherche LDAP: {ex}")
                    break
            
            conn.unbind()
            
            if not results:
                raise Exception(f"Aucun résultat trouvé avec le filtre LDAP: {ldap_filter}")
            
            return results
            
        except Exception as ex:
            logger.error(f"Erreur lors de la recherche LDAP dans {search_base}: {ex}")
            raise
    
    @staticmethod
    def test_connection(domain_fqdn: str) -> bool:
        """
        Teste la connectivité LDAP avec le domaine.
        
        Args:
            domain_fqdn: FQDN du domaine
            
        Returns:
            True si la connexion réussit, False sinon
        """
        try:
            LdapUtils.get_root_dse(domain_fqdn)
            return True
        except Exception as ex:
            logger.error(f"Test de connexion LDAP échoué pour {domain_fqdn}: {ex}")
            return False
