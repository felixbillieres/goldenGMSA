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

```bash
# Énumérer tous les gMSA
python main.py gmsainfo

# Interroger un gMSA spécifique par SID
python main.py gmsainfo --sid <SID_GMSA>

# Dumper toutes les clés racine KDS
python main.py kdsinfo

# Calculer le mot de passe d'un gMSA
python main.py compute --sid <SID_GMSA>

# Voir toutes les options
python main.py --help
```

## Avertissement

Cet outil est destiné uniquement à des fins de **test de pénétration autorisé** et de **recherche en sécurité**. L'utilisation de cet outil sur des systèmes sans autorisation explicite est **illégale**.

## Licence

MIT License

## Auteur

**Félix Billières (Elliot Belt)**

## Crédits

Basé sur la recherche de Yuval Gordon ([@YuG0rd](https://twitter.com/YuG0rd)) - [Introducing the Golden GMSA Attack](https://www.semperis.com/blog/golden-gmsa-attack/)
