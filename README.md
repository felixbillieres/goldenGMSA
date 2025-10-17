# GoldenGMSA Python

Équivalence Python de l'outil GoldenGMSA pour l'exploitation des Group Managed Service Accounts (gMSA) dans Active Directory.

## Installation

```bash
# Cloner le repository
git clone https://github.com/felixbillieres/goldenGMSA.git
cd goldenGMSA/golden_gmsa_python

# Créer un environnement virtuel
python3 -m venv venv
source venv/bin/activate

# Installer les dépendances
pip install -r requirements.txt
```

## Utilisation

### Authentification au domaine

```bash
# Avec authentification (recommandé)
python main.py -u 'DOMAIN\username' -p 'password' --domain domain.local gmsainfo

# Ou avec format UPN
python main.py -u 'user@domain.local' -p 'password' --domain domain.local gmsainfo

# Avec IP du contrôleur de domaine
python main.py -u 'user@domain.local' -p 'password' --domain domain.local --dc-ip 192.168.1.10 gmsainfo

# Avec LDAPS (SSL)
python main.py -u 'user@domain.local' -p 'password' --domain domain.local --use-ssl gmsainfo
```

### Commandes disponibles

```bash
# Énumérer tous les gMSA du domaine
python main.py -u 'user@domain.local' -p 'password' --domain domain.local gmsainfo

# Interroger un gMSA spécifique par SID
python main.py -u 'user@domain.local' -p 'password' --domain domain.local gmsainfo --sid <SID_GMSA>

# Dumper toutes les clés racine KDS
python main.py -u 'user@domain.local' -p 'password' --domain domain.local kdsinfo

# Calculer le mot de passe d'un gMSA
python main.py -u 'user@domain.local' -p 'password' --domain domain.local compute --sid <SID_GMSA>

# Mode hors ligne (sans authentification, avec clés exportées)
python main.py compute --sid <SID_GMSA> --kdskey <BASE64_KEY> --pwdid <BASE64_PWDID>

# Voir toutes les options
python main.py --help
```

### Formats d'authentification supportés

- **UPN** : `user@domain.local`
- **NetBIOS** : `DOMAIN\username`
- **Simple** : `username` (le domaine sera ajouté automatiquement)

## Avertissement

Cet outil est destiné uniquement à des fins de **test de pénétration autorisé** et de **recherche en sécurité**. L'utilisation de cet outil sur des systèmes sans autorisation explicite est **illégale**.

## Licence

MIT License

## Auteur

**Félix Billières (Elliot Belt)**

## Crédits

Basé sur la recherche de Yuval Gordon ([@YuG0rd](https://twitter.com/YuG0rd)) - [Introducing the Golden GMSA Attack](https://www.semperis.com/blog/golden-gmsa-attack/)
