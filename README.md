# NetExec Share Audit Module

A NetExec module for enumerating SMB share permissions during penetration tests and security assessments.

## Disclaimer

This thing is totally vibe-coded, and I'm not ashamed about it.

## Purpose

This module helps penetration testers quickly identify network shares with overly permissive access controls. It displays not only the shares themselves but also the **share-level permissions (Share ACLs)**, which is crucial for security risk assessment.

### Use Case

During penetration tests, sensitive data is frequently found in network shares. There's a significant difference between a share containing sensitive data that is:
- Shared with a small AD group of 4 users ✅
- Or configured as "Everyone - Full Control" ⚠️

After obtaining Domain Admin privileges, this module allows you to quickly scan the entire network for misconfigured shares.

## Features

- ✅ Enumerates all SMB shares on remote hosts
- ✅ Displays share-level permissions (Share Permissions)
- ✅ Translates SIDs to readable names (Everyone, Authenticated Users, etc.)
- ✅ Translates access masks to understandable rights (Full Control, Change, Read)
- ✅ Highlights dangerous configurations ("Everyone - Full Control", etc.)
- ✅ Filters administrative shares by default (ADMIN$, C$, IPC$)
- ✅ Works via SMB/RPC (no WinRM required)
- ✅ Supports authentication with username/password or hash

## Installation

### Prerequisites

- [NetExec](https://github.com/Pennyw0rth/NetExec) installed
- [Impacket](https://github.com/fortra/impacket) library (usually installed with NetExec)
- Valid domain credentials with at least read access

### Install Module

**1. Copy module to NetExec module directory:**

```bash
# Linux/macOS
cp share_audit.py ~/.nxc/modules/

# Windows
copy share_audit.py %USERPROFILE%\.nxc\modules\
```

**2. Alternative: Use module from current directory:**

NetExec can also load modules from the current directory:

```bash
nxc smb <target> -u <user> -p <pass> -M ./share_audit.py
```

## Usage

### Basic scan of a single host:

```bash
nxc smb 192.168.1.10 -u administrator -p 'P@ssw0rd' -M share_audit
```

### Network-wide scan:

```bash
nxc smb 192.168.1.0/24 -u administrator -p 'P@ssw0rd' -M share_audit
```

### With NTLM hash (Pass-the-Hash):

```bash
nxc smb 192.168.1.10 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0' -M share_audit
```

### With domain credentials:

```bash
nxc smb 192.168.1.10 -u administrator -p 'P@ssw0rd' -d CONTOSO -M share_audit
```

### Include administrative shares:

```bash
nxc smb 192.168.1.10 -u administrator -p 'P@ssw0rd' -M share_audit -o FILTER_ADMIN=false
```

### Local authentication:

```bash
nxc smb 192.168.1.10 -u administrator -p 'P@ssw0rd' --local-auth -M share_audit
```

## Module Options

| Option | Default | Description |
|--------|---------|-------------|
| `FILTER_ADMIN` | `true` | Filter out administrative shares (ADMIN$, C$, IPC$, etc.) |
| `DETAILED` | `false` | Show detailed ACL information (currently unused) |

## Output Example

```
SMB         192.168.1.10    445    DC01             [*] Windows Server 2019 (name:DC01) (domain:contoso.local)
SMB         192.168.1.10    445    DC01             [+] contoso.local\administrator:P@ssw0rd (Pwn3d!)
SHARE_AUDIT 192.168.1.10    445    DC01             [+] Found 2 share(s)
SHARE_AUDIT 192.168.1.10    445    DC01             [!] Share: Finance [Disk]
SHARE_AUDIT 192.168.1.10    445    DC01             [+]   Comment: Financial Documents
SHARE_AUDIT 192.168.1.10    445    DC01             [+]   Permissions:
SHARE_AUDIT 192.168.1.10    445    DC01                 [!] Everyone: Full Control (ACCESS_ALLOWED_ACE)
SHARE_AUDIT 192.168.1.10    445    DC01             [+] Share: IT [Disk]
SHARE_AUDIT 192.168.1.10    445    DC01             [+]   Comment: IT Department Files
SHARE_AUDIT 192.168.1.10    445    DC01             [+]   Permissions:
SHARE_AUDIT 192.168.1.10    445    DC01             [+]     - Administrators: Full Control (ACCESS_ALLOWED_ACE)
SHARE_AUDIT 192.168.1.10    445    DC01             [+]     - IT-Team: Change (ACCESS_ALLOWED_ACE)
SHARE_AUDIT 192.168.1.10    445    DC01             [+]     - Authenticated Users: Read (ACCESS_ALLOWED_ACE)
```

**Legend:**
- `[!]` = Dangerous configuration (highlighted in red/orange)
- `[+]` = Normal configuration (green)

## What Does This Module Check?

### Share Permissions vs. NTFS Permissions

⚠️ **Important:** This module displays **share-level permissions** (Share ACLs), not NTFS file system permissions.

Effective permissions are the **most restrictive** combination of both:
- Share Permission: Everyone - Full Control
- NTFS Permission: Domain Users - Read

→ Effective: Domain Users - Read

However, "Everyone - Full Control" at the share level is still a security finding as it unnecessarily increases the attack surface and can lead to information disclosure.

### Permission Levels Detected

The module recognizes and translates the following permissions:

| Permission | Hex Value | Description |
|------------|-----------|-------------|
| **Full Control** | `0x001F01FF` | Complete access (read, write, delete, change permissions) |
| **Change** | `0x001301BF` | Read, write, and delete |
| **Read** | `0x001200A9` | Read-only access |
| **Custom** | Various | Individual permission combinations |

### Well-Known SIDs Translated

Known SIDs are automatically translated to readable names:

| SID | Name | Description |
|-----|------|-------------|
| `S-1-1-0` | Everyone | All users, including anonymous |
| `S-1-5-7` | Anonymous | Anonymous users |
| `S-1-5-11` | Authenticated Users | All authenticated users |
| `S-1-5-18` | SYSTEM | Local system account |
| `S-1-5-32-544` | Administrators | Built-in administrators group |
| `S-1-5-32-545` | Users | Built-in users group |
| `S-1-5-32-546` | Guests | Built-in guests group |

## Dangerous Configurations

The module automatically highlights dangerous configurations:

- ⚠️ **Everyone** with Full Control or Change permissions
- ⚠️ **Anonymous** with any permissions
- ⚠️ **Guests** with write permissions
- ⚠️ Missing DACL (implicitly grants Everyone Full Control)

## Technical Details

### Protocol & API Calls

- **Protocol**: SMB over RPC (MS-SRVS)
- **RPC Interface**: MSRPC_UUID_SRVS
- **API Calls**:
  - `NetrShareEnum` (Level 1) - Enumerate shares
  - `NetrShareGetInfo` (Level 502) - Retrieve security descriptor
- **Library**: Impacket
- **Authentication**: Username/Password, NTLM Hash, or Kerberos

### Implementation Details

The module:
1. Establishes RPC connection via `\\pipe\\srvsvc`
2. Enumerates shares using `hNetrShareEnum`
3. Retrieves security descriptors using `hNetrShareGetInfo` (Level 502)
4. Parses security descriptors using `ldaptypes.SR_SECURITY_DESCRIPTOR`
5. Iterates through DACL ACEs to extract permissions
6. Translates SIDs and access masks to human-readable format

## Troubleshooting

### "Access Denied" for certain shares

Some shares can only be accessed by specific groups. The module will display "ACCESS DENIED" for these shares. This is expected behavior when the authenticated user lacks sufficient privileges.

**Solution:** Use credentials with higher privileges (e.g., Domain Admin account).

### Module not found

Ensure the module is in the correct directory:

```bash
# Check module directory
ls -la ~/.nxc/modules/

# Or load module directly with path
nxc smb <target> -u <user> -p <pass> -M /path/to/share_audit.py
```

### RPC connection errors

Verify that:
- Port 445 (SMB) is reachable
- Credentials are correct
- Target host is online and responding
- Firewall allows SMB traffic

### "No security descriptor available"

This can occur when:
- The share doesn't have a security descriptor set
- Access is denied to retrieve the security descriptor
- The share is a special administrative share

## Penetration Testing Reporting Tips

When documenting findings:

1. **Screenshot/Command Output**: Include the nxc scan output
2. **Context**: What sensitive data was found on the share?
3. **Risk Assessment**: How many users belong to the privileged group?
4. **Impact**: What could an attacker do with this access?
5. **Recommendation**: Apply least privilege principle - grant only necessary permissions
6. **CVSS/Severity**: Depends on data sensitivity and exposure

### Example Finding

```
Title: Sensitive Share with Overly Permissive Access Controls

Affected Share: \\DC01\Finance
Current Permissions: Everyone - Full Control
Share Contents: Payroll data, financial reports, tax documents
Risk: All domain users (500+) can access, modify, and delete sensitive financial data

Impact:
- Information Disclosure (CWE-200)
- Unauthorized Access to Sensitive Data
- Potential Data Manipulation/Destruction
- Regulatory Compliance Violation (GDPR, SOX, HIPAA)

Recommendation:
1. Restrict share permissions to "Finance-Team - Change"
2. Apply restrictive NTFS permissions (e.g., Finance-Admins: Full Control, Finance-Users: Read)
3. Implement audit logging for share access
4. Consider encrypting sensitive documents at rest
5. Regular access reviews and permission audits

Severity: High (CVSS 7.5)
```

## Comparison with Built-in NetExec Features

NetExec includes a `--shares` flag that lists shares and indicates whether you can read/write to them. This module provides **additional value** by:

| Feature | `nxc --shares` | `share_audit` module |
|---------|----------------|---------------------|
| Lists shares | ✅ | ✅ |
| Shows your access | ✅ | ❌ |
| Shows share permissions (ACLs) | ❌ | ✅ |
| Identifies dangerous configs | ❌ | ✅ |
| Translates SIDs | ❌ | ✅ |
| Filters admin shares | ❌ | ✅ |

**Use `--shares`** to quickly check *your* access level.
**Use `share_audit`** to analyze *share-level permissions* and identify misconfigurations.

## Security Considerations

### OPSEC

- **OPSEC Safe**: Yes - Uses standard Windows RPC calls
- **Detection Risk**: Low - Legitimate administrative activity
- **EDR/AV Impact**: Minimal - No malicious behavior
- **Logging**: Activity may be logged in Windows Security Event Log (Event ID 5140, 5145)

### Ethical Use

This tool is intended for:
- ✅ Authorized penetration tests
- ✅ Security audits with written approval
- ✅ Red team exercises with proper authorization
- ✅ Internal security assessments

**Never use this tool without explicit written authorization from the system owner.**

## License

MIT License - Free to use for penetration testing and security audits.

## Credits

- **Author**: Created for the Offensive Security Community
- **Built with**: [NetExec](https://github.com/Pennyw0rth/NetExec) by Pennyw0rth
- **Dependencies**: [Impacket](https://github.com/fortra/impacket) by Fortra

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for:
- Bug fixes
- Feature enhancements
- Documentation improvements
- Additional well-known SID translations

## Changelog

### v1.0.0 (2026-02-07)
- Initial release
- Share enumeration via RPC
- Security descriptor parsing
- SID translation
- Permission translation
- Dangerous configuration detection
- Administrative share filtering

## Disclaimer

**FOR AUTHORIZED SECURITY TESTING ONLY**

This tool is designed for legitimate security assessments and penetration tests. Only use on systems for which you have explicit written authorization. Unauthorized access to computer systems is illegal.

The authors assume no liability for misuse or damage caused by this tool.
