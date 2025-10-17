"""
Utilitaires pour les opérations LDAP avec Active Directory.
"""

import logging
import socket
from typing import List, Optional, Dict, Any
import ldap
import ldap.filter

logger = logging.getLogger(__name__)


class LdapConnection:
    """
    Classe pour gérer une connexion LDAP avec credentials.
    """
    
    def __init__(self, domain: str, username: Optional[str] = None, 
                 password: Optional[str] = None, use_ssl: bool = False,
                 dc_ip: Optional[str] = None):
        """
        Initialise une connexion LDAP.
        
        Args:
            domain: Nom de domaine (FQDN)
            username: Nom d'utilisateur (format: user@domain.com ou DOMAIN\\user)
            password: Mot de passe
            use_ssl: Utiliser LDAPS (port 636)
            dc_ip: Adresse IP du contrôleur de domaine (optionnel)
        """
        self.domain = domain
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.dc_ip = dc_ip
        self.conn = None
        self._root_dse_cache = None
        
    def connect(self):
        """Établit la connexion LDAP."""
        try:
            target = self.dc_ip if self.dc_ip else self.domain
            protocol = "ldaps" if self.use_ssl else "ldap"
            port = 636 if self.use_ssl else 389
            server_uri = f"{protocol}://{target}:{port}"
            
            logger.info(f"Connexion à {server_uri}...")
            
            self.conn = ldap.initialize(server_uri)
            self.conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
            self.conn.set_option(ldap.OPT_REFERRALS, 0)
            self.conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 10)
            
            if self.use_ssl:
                self.conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            
            if self.username and self.password:
                bind_dn = self._format_bind_dn(self.username)
                logger.info(f"Authentification avec {bind_dn}...")
                self.conn.simple_bind_s(bind_dn, self.password)
                logger.info("Authentification réussie")
            else:
                logger.info("Connexion anonyme...")
                self.conn.simple_bind_s("", "")
                
        except ldap.INVALID_CREDENTIALS:
            logger.error("Credentials invalides")
            raise Exception("Authentification échouée: credentials invalides")
        except ldap.SERVER_DOWN:
            logger.error(f"Impossible de joindre le serveur {target}")
            raise Exception(f"Serveur LDAP injoignable: {target}")
        except Exception as ex:
            logger.error(f"Erreur de connexion LDAP: {ex}")
            raise
            
    def _format_bind_dn(self, username: str) -> str:
        """
        Formate le DN de bind selon le format fourni.
        
        Args:
            username: Nom d'utilisateur
            
        Returns:
            DN formaté
        """
        if '@' in username:
            return username
        elif '\\' in username:
            return username.split('\\')[1] + '@' + self.domain
        else:
            return username + '@' + self.domain
            
    def disconnect(self):
        """Ferme la connexion LDAP."""
        if self.conn:
            try:
                self.conn.unbind_s()
                logger.info("Connexion LDAP fermée")
            except:
                pass
                
    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()


class LdapUtils:
    """
    Classe utilitaire pour les opérations LDAP avec Active Directory.
    """
    
    # Variable globale pour stocker la connexion courante
    _current_connection: Optional[LdapConnection] = None
    
    @staticmethod
    def set_connection(connection: LdapConnection):
        """
        Définit la connexion LDAP à utiliser pour toutes les opérations.
        
        Args:
            connection: Instance de LdapConnection
        """
        LdapUtils._current_connection = connection
        
    @staticmethod
    def get_connection() -> Optional[LdapConnection]:
        """
        Retourne la connexion LDAP courante.
        
        Returns:
            Instance de LdapConnection ou None
        """
        return LdapUtils._current_connection
    
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
    def get_root_dse(domain_fqdn: str = None) -> Dict[str, Any]:
        """
        Récupère les informations RootDSE.
        
        Args:
            domain_fqdn: FQDN du domaine (optionnel si une connexion est active)
            
        Returns:
            Dictionnaire contenant les informations RootDSE
        """
        try:
            conn_obj = LdapUtils._current_connection
            
            if conn_obj and conn_obj.conn:
                if conn_obj._root_dse_cache:
                    return conn_obj._root_dse_cache
                    
                result = conn_obj.conn.search_s("", ldap.SCOPE_BASE, "(objectClass=*)")
                if result and len(result) > 0:
                    conn_obj._root_dse_cache = result[0][1]
                    return conn_obj._root_dse_cache
                else:
                    raise Exception("Impossible de récupérer les informations RootDSE")
            else:
                if not domain_fqdn:
                    raise ValueError("domain_fqdn requis si aucune connexion active")
                    
                domain_escaped = ldap.filter.escape_filter_chars(domain_fqdn)
                server_uri = f"ldap://{domain_escaped}"
                
                conn = ldap.initialize(server_uri)
                conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
                conn.set_option(ldap.OPT_REFERRALS, 0)
                
                result = conn.search_s("", ldap.SCOPE_BASE, "(objectClass=*)")
                conn.unbind()
                
                if result and len(result) > 0:
                    return result[0][1]
                else:
                    raise Exception("Impossible de récupérer les informations RootDSE")
                
        except Exception as ex:
            logger.error(f"Erreur lors de la récupération RootDSE: {ex}")
            raise
    
    @staticmethod
    def get_current_domain() -> str:
        """
        Détermine le domaine actuel en utilisant les informations système ou la connexion active.
        
        Returns:
            Nom du domaine actuel
        """
        try:
            conn_obj = LdapUtils._current_connection
            if conn_obj:
                return conn_obj.domain
                
            hostname = socket.getfqdn()
            if '.' in hostname:
                return hostname.split('.', 1)[1]
            
            return hostname
            
        except Exception as ex:
            logger.warning(f"Impossible de déterminer le domaine actuel: {ex}")
            return "localhost"
    
    @staticmethod
    def get_current_forest() -> str:
        """
        Détermine la forêt actuelle.
        
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
            conn_obj = LdapUtils._current_connection
            
            if conn_obj and conn_obj.conn:
                conn = conn_obj.conn
                should_close = False
            else:
                domain_escaped = ldap.filter.escape_filter_chars(domain_fqdn)
                server_uri = f"ldap://{domain_escaped}"
                
                conn = ldap.initialize(server_uri)
                conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
                conn.set_option(ldap.OPT_REFERRALS, 0)
                conn.simple_bind_s("", "")
                should_close = True
            
            results = []
            page_size = 100
            
            page_control = ldap.controls.SimplePagedResultsControl(True, size=page_size, cookie='')
            
            while True:
                try:
                    msgid = conn.search_ext(
                        search_base,
                        ldap.SCOPE_SUBTREE,
                        ldap_filter,
                        attributes,
                        serverctrls=[page_control]
                    )
                    
                    result_type, result_data, result_msgid, result_controls = conn.result3(msgid)
                    
                    for dn, attrs in result_data:
                        if dn:
                            results.append(attrs)
                    
                    page_control = None
                    for control in result_controls:
                        if control.controlType == ldap.controls.SimplePagedResultsControl.controlType:
                            page_control = control
                            break
                    
                    if not page_control or not page_control.cookie:
                        break
                        
                except ldap.SIZELIMIT_EXCEEDED:
                    logger.warning("Limite de taille LDAP atteinte")
                    break
                except Exception as ex:
                    logger.error(f"Erreur lors de la recherche LDAP: {ex}")
                    break
            
            if should_close:
                conn.unbind()
            
            if not results:
                logger.warning(f"Aucun résultat trouvé avec le filtre LDAP: {ldap_filter}")
                return []
            
            return results
            
        except Exception as ex:
            logger.error(f"Erreur lors de la recherche LDAP dans {search_base}: {ex}")
            raise
