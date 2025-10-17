# Changelog

## [1.1.0] - 2025-10-17

### ✨ Nouvelles fonctionnalités

#### Authentification LDAP depuis Linux
- **Classe `LdapConnection`** : Gestion complète des connexions LDAP authentifiées
- **Support multi-formats** :
  - UPN : `user@domain.com`
  - NetBIOS : `DOMAIN\username`
  - Simple : `username` (domaine ajouté automatiquement)
- **Options de connexion** :
  - `--username` / `-u` : Nom d'utilisateur
  - `--password` / `-p` : Mot de passe
  - `--dc-ip` : Adresse IP du contrôleur de domaine
  - `--use-ssl` : Utiliser LDAPS (port 636) au lieu de LDAP (port 389)

#### Amélioration de l'exploitation
- Énumération complète des gMSA depuis un host Linux avec credentials
- Extraction des clés racine KDS avec authentification
- Calcul des mots de passe gMSA en mode authentifié
- Gestion automatique de la connexion/déconnexion LDAP
- Cache des informations RootDSE pour optimiser les performances

#### Documentation
- **USAGE_EXAMPLES.md** : Guide complet d'utilisation avec exemples pratiques
- **README.md** mis à jour avec instructions d'authentification
- Support des scénarios d'utilisation programmatique en Python

### 🔧 Améliorations techniques

#### Module `ldap_utils.py`
- Nouvelle classe `LdapConnection` avec context manager
- Méthodes de recherche LDAP utilisant la connexion authentifiée
- Fallback sur connexion anonyme si aucune authentification
- Gestion robuste des erreurs (credentials invalides, serveur injoignable)

#### Module `main.py`
- Arguments d'authentification globaux disponibles pour toutes les commandes
- Initialisation automatique de la connexion LDAP au démarrage
- Nettoyage propre de la connexion en fin d'exécution
- Messages informatifs sur l'état de la connexion

#### Sécurité
- Validation des credentials avant connexion
- Support de LDAPS pour connexions chiffrées
- Timeout de connexion configuré (10 secondes)
- Masquage des mots de passe dans les logs

### 📝 Exemples d'utilisation

```bash
# Énumération avec authentification
python main.py -u 'user@domain.local' -p 'password' --domain domain.local gmsainfo

# Avec IP du DC
python main.py -u 'user@domain.local' -p 'password' --domain domain.local --dc-ip 192.168.1.10 gmsainfo

# Avec SSL
python main.py -u 'user@domain.local' -p 'password' --domain domain.local --use-ssl kdsinfo

# Calcul de mot de passe
python main.py -u 'user@domain.local' -p 'password' --domain domain.local compute --sid <SID>
```

### 🎯 Cas d'usage

L'outil permet maintenant d'exploiter GoldenGMSA **directement depuis un host Linux** ayant :
- ✅ Accès réseau au contrôleur de domaine
- ✅ Credentials valides (utilisateur standard ou privilégié)
- ✅ Connectivité LDAP/LDAPS (port 389 ou 636)

**Scénarios typiques** :
1. Pentester depuis Kali Linux vers un domaine Windows
2. Red Team depuis un jump host Linux compromis
3. Audit de sécurité depuis un poste Linux d'administration
4. Automatisation de tests depuis pipelines CI/CD Linux

### 🔄 Compatibilité

- ✅ Python 3.7+
- ✅ Linux (toutes distributions)
- ✅ Active Directory 2012 R2 et supérieur
- ✅ Mode hors ligne conservé (sans authentification)

---

## [1.0.0] - 2025-10-17

### 🎉 Version initiale

- Implémentation Python de GoldenGMSA
- Énumération des gMSA
- Extraction des clés racine KDS
- Calcul des mots de passe gMSA
- Mode hors ligne
- Support LDAP basique
- Documentation complète

