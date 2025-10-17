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
    Class to manage LDAP connection with credentials.
    Supports: Password, Pass-the-Hash (PTH), Pass-the-Ticket (PTT)
    """
    
    def __init__(self, domain: str, username: Optional[str] = None, 
                 password: Optional[str] = None, use_ssl: bool = False,
                 dc_ip: Optional[str] = None,
                 nt_hash: Optional[str] = None,
                 lm_hash: Optional[str] = None,
                 aes_key: Optional[str] = None,
                 ccache: Optional[str] = None,
                 use_kerberos: bool = False):
        """
        Initialize LDAP connection.
        
        Args:
            domain: Domain name (FQDN)
            username: Username (format: user@domain.com or DOMAIN\\user)
            password: Password
            use_ssl: Use LDAPS (port 636)
            dc_ip: Domain controller IP address (optional)
            nt_hash: NTLM hash for Pass-the-Hash
            lm_hash: LM hash for Pass-the-Hash (optional)
            aes_key: AES key for Kerberos
            ccache: Kerberos ccache file for Pass-the-Ticket
            use_kerberos: Force Kerberos usage
        """
        self.domain = domain
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.dc_ip = dc_ip
        self.nt_hash = nt_hash
        self.lm_hash = lm_hash
        self.aes_key = aes_key
        self.ccache = ccache
        self.use_kerberos = use_kerberos
        self.conn = None
        self._root_dse_cache = None
        self._use_advanced_auth = nt_hash or ccache or aes_key or use_kerberos
        self._is_ldap3 = False
        
    def connect(self):
        """Establish LDAP connection."""
        # If using PTH/PTT, use ldap3 or impacket
        if self._use_advanced_auth:
            self._connect_advanced()
        else:
            self._connect_simple()
    
    def _connect_simple(self):
        """Simple LDAP connection with python-ldap."""
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
    
    def _connect_advanced(self):
        """Advanced LDAP connection with PTH/PTT via ldap3."""
        try:
            from .auth import AuthMethod, create_ldap3_connection
            
            # Créer l'objet d'authentification
            auth = AuthMethod(
                username=self.username,
                password=self.password,
                nt_hash=self.nt_hash,
                lm_hash=self.lm_hash,
                aes_key=self.aes_key,
                ccache=self.ccache,
                use_kerberos=self.use_kerberos
            )
            
            target = self.dc_ip if self.dc_ip else self.domain
            logger.info(f"Connexion LDAP avancée ({auth.auth_mode}) à {target}...")
            
            # Créer la connexion avec ldap3
            self.conn = create_ldap3_connection(
                self.domain,
                auth,
                self.dc_ip,
                self.use_ssl
            )
            
            # Marquer que c'est une connexion ldap3
            self._is_ldap3 = True
            
            logger.info(f"Authentification réussie ({auth})")
            
        except ImportError as e:
            logger.error(f"ldap3 requis pour PTH/PTT. Installer avec: pip install ldap3")
            raise
        except Exception as ex:
            logger.error(f"Erreur de connexion LDAP avancée: {ex}")
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
        """Close LDAP connection."""
        if self.conn:
            try:
                if self._is_ldap3:
                    self.conn.unbind()
                else:
                    self.conn.unbind_s()
                logger.info("LDAP connection closed")
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
                
                # Check if using ldap3
                if hasattr(conn_obj, '_is_ldap3') and conn_obj._is_ldap3:
                    from ldap3 import BASE
                    conn_obj.conn.search(
                        search_base='',
                        search_filter='(objectClass=*)',
                        search_scope=BASE,
                        attributes=['*']
                    )
                    if conn_obj.conn.entries:
                        # Convert ldap3 entry to dict
                        entry = conn_obj.conn.entries[0]
                        root_dse = {}
                        for attr in entry.entry_attributes:
                            val = getattr(entry, attr)
                            if hasattr(val, 'raw_values'):
                                root_dse[attr] = val.raw_values
                            elif hasattr(val, 'value'):
                                v = val.value
                                root_dse[attr] = [v.encode('utf-8') if isinstance(v, str) else v]
                        conn_obj._root_dse_cache = root_dse
                        return root_dse
                    else:
                        raise Exception("Unable to retrieve RootDSE information")
                else:
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
    def _perform_ldap3_search(conn, search_base: str, ldap_filter: str, attributes: List[str]) -> List[Dict[str, Any]]:
        """
        Perform LDAP search using ldap3 library.
        
        Args:
            conn: ldap3 Connection object
            search_base: Search base DN
            ldap_filter: LDAP filter
            attributes: List of attributes to retrieve
            
        Returns:
            List of search results in python-ldap compatible format
        """
        try:
            from ldap3 import SUBTREE
            
            # Perform search with ldap3
            conn.search(
                search_base=search_base,
                search_filter=ldap_filter,
                search_scope=SUBTREE,
                attributes=attributes
            )
            
            # Convert ldap3 results to python-ldap format
            results = []
            for entry in conn.entries:
                attrs = {}
                for attr_name in attributes:
                    if hasattr(entry, attr_name):
                        attr_value = getattr(entry, attr_name)
                        if hasattr(attr_value, 'value'):
                            # Get raw value
                            raw_value = attr_value.value
                            if isinstance(raw_value, str):
                                attrs[attr_name] = [raw_value.encode('utf-8')]
                            elif isinstance(raw_value, bytes):
                                attrs[attr_name] = [raw_value]
                            elif isinstance(raw_value, list):
                                attrs[attr_name] = [v.encode('utf-8') if isinstance(v, str) else v for v in raw_value]
                            else:
                                attrs[attr_name] = [str(raw_value).encode('utf-8')]
                        elif hasattr(attr_value, 'raw_values'):
                            # Get raw bytes directly
                            attrs[attr_name] = attr_value.raw_values
                
                if attrs:
                    results.append(attrs)
            
            if not results:
                logger.warning(f"No results found with LDAP filter: {ldap_filter}")
                return []
            
            return results
            
        except Exception as ex:
            logger.error(f"Error during ldap3 search in {search_base}: {ex}")
            raise
    
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
            
            # Check if using ldap3 for PTH/PTT
            if conn_obj and hasattr(conn_obj, '_is_ldap3') and conn_obj._is_ldap3:
                return LdapUtils._perform_ldap3_search(conn_obj.conn, search_base, ldap_filter, attributes)
            
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
