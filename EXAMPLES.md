# Share Audit - Praktische Beispiele

## Szenario 1: Domain Admin - Netzwerk-weiter Scan

Nach dem Erlangen von Domain Admin Rechten möchtest du alle Server im Netzwerk auf problematische Share-Berechtigungen scannen.

```bash
# Subnet scannen
nxc smb 192.168.1.0/24 -u administrator -p 'SecureP@ss123' -d CONTOSO -M share_audit

# Mehrere Subnets
nxc smb 192.168.1.0/24 192.168.2.0/24 10.0.0.0/24 -u administrator -p 'SecureP@ss123' -d CONTOSO -M share_audit

# Mit Target-Liste aus Datei
nxc smb targets.txt -u administrator -p 'SecureP@ss123' -M share_audit
```

**Output filtern für gefährliche Shares:**
```bash
nxc smb 192.168.1.0/24 -u administrator -p 'SecureP@ss123' -M share_audit 2>&1 | grep -i "everyone\|anonymous"
```

## Szenario 2: Pass-the-Hash nach Credential Dump

Nach einem erfolgreichen Mimikatz/Secretsdump und du hast NTLM-Hashes:

```bash
# Mit NTLM Hash
nxc smb 192.168.1.10 -u administrator -H '31d6cfe0d16ae931b73c59d7e0c089c0' -M share_audit

# Mit LM:NTLM Hash Format
nxc smb 192.168.1.10 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0' -M share_audit

# Multiple Hashes testen
nxc smb 192.168.1.0/24 -u users.txt -H hashes.txt -M share_audit --continue-on-success
```

## Szenario 3: Gezielte Server-Analyse

Du hast bereits interessante Server identifiziert (z.B. Fileserver, DC):

```bash
# Fileserver im Detail
nxc smb fileserver01.contoso.local -u administrator -p 'SecureP@ss123' -M share_audit -o DETAILED=true

# Alle Domain Controllers
nxc smb dc01.contoso.local dc02.contoso.local -u administrator -p 'SecureP@ss123' -M share_audit

# Mit Hostname-Liste
echo "fileserver01.contoso.local
fileserver02.contoso.local
sharepoint.contoso.local" > fileservers.txt

nxc smb fileservers.txt -u administrator -p 'SecureP@ss123' -M share_audit
```

## Szenario 4: Kombination mit anderen nxc Modulen

Share Audit in Kombination mit anderen Enumerations-Techniken:

```bash
# Erst Hosts finden
nxc smb 192.168.1.0/24

# Dann Shares scannen
nxc smb 192.168.1.0/24 -u administrator -p 'SecureP@ss123' -M share_audit

# Zusätzlich nach sensitive Files suchen (spider_plus Modul)
nxc smb 192.168.1.0/24 -u administrator -p 'SecureP@ss123' -M spider_plus

# Dann gezielt auf problematischen Shares nach Keywords suchen
nxc smb 192.168.1.10 -u administrator -p 'SecureP@ss123' --shares Finance$ --get-file "passwords.xlsx"
```

## Szenario 5: Output für Reporting speichern

```bash
# JSON Output für automatische Verarbeitung
nxc smb 192.168.1.0/24 -u administrator -p 'SecureP@ss123' -M share_audit > share_audit_$(date +%Y%m%d).txt

# Mit Timestamp und Log
nxc smb 192.168.1.0/24 -u administrator -p 'SecureP@ss123' -M share_audit 2>&1 | tee share_audit_$(date +%Y%m%d_%H%M%S).log

# Nur gefährliche Findings extrahieren
nxc smb 192.168.1.0/24 -u administrator -p 'SecureP@ss123' -M share_audit 2>&1 | grep "\[!\]" > dangerous_shares.txt
```

## Szenario 6: Nach Kompromittierung eines Service Accounts

Du hast einen Service Account kompromittiert und möchtest prüfen auf welche Shares dieser Zugriff hat:

```bash
# Service Account testen
nxc smb 192.168.1.0/24 -u svc_backup -p 'BackupP@ss' -M share_audit

# Prüfen ob der Service Account übermäßige Rechte hat
nxc smb fileserver01 -u svc_backup -p 'BackupP@ss' -M share_audit
```

## Erwartete Output-Beispiele

### Beispiel 1: Gefährliche Konfiguration

```
SHARE_AUD   192.168.1.10    445    FS01    [!] Share: CompanyData [Disk]
SHARE_AUD   192.168.1.10    445    FS01      Comment: Shared Company Files
SHARE_AUD   192.168.1.10    445    FS01      Permissions:
SHARE_AUD   192.168.1.10    445    FS01        [!] Everyone: Full Control (ACCESS_ALLOWED_ACE)
SHARE_AUD   192.168.1.10    445    FS01        - Administrators: Full Control (ACCESS_ALLOWED_ACE)
```

**Interpretation:** ⚠️ CRITICAL Finding - "Everyone" hat Full Control auf CompanyData Share!

### Beispiel 2: Sichere Konfiguration

```
SHARE_AUD   192.168.1.10    445    FS01    [*] Share: HR-Private [Disk]
SHARE_AUD   192.168.1.10    445    FS01      Comment: HR Department Only
SHARE_AUD   192.168.1.10    445    FS01      Permissions:
SHARE_AUD   192.168.1.10    445    FS01        - Administrators: Full Control (ACCESS_ALLOWED_ACE)
SHARE_AUD   192.168.1.10    445    FS01        - S-1-5-21-xxx-xxx-xxx-1105: Change (ACCESS_ALLOWED_ACE)
```

**Interpretation:** ✅ Gut konfiguriert - Nur Admins und eine spezifische Gruppe (SID) haben Zugriff.

### Beispiel 3: Anonymous Access

```
SHARE_AUD   192.168.1.10    445    FS01    [!] Share: Public [Disk]
SHARE_AUD   192.168.1.10    445    FS01      Permissions:
SHARE_AUD   192.168.1.10    445    FS01        [!] Anonymous: Read (ACCESS_ALLOWED_ACE)
SHARE_AUD   192.168.1.10    445    FS01        [!] Everyone: Read (ACCESS_ALLOWED_ACE)
```

**Interpretation:** ⚠️ HIGH Finding - Anonymous (unauthenticated) Zugriff möglich!

### Beispiel 4: Access Denied

```
SHARE_AUD   192.168.1.10    445    FS01    [*] Share: AdminOnly [Disk]
SHARE_AUD   192.168.1.10    445    FS01      Permissions:
SHARE_AUD   192.168.1.10    445    FS01        - ACCESS DENIED
```

**Interpretation:** Der verwendete Account hat keine Berechtigung die Share-Permissions zu lesen (vermutlich gut geschützt).

## Integration in Pentest-Workflow

### Phase 1: Initial Access & Credential Gathering
```bash
# Nach Initial Access - lokale Enumeration
nxc smb localhost -u localadmin -p 'P@ss' -M share_audit
```

### Phase 2: Lateral Movement
```bash
# Entdeckte Credentials nutzen
nxc smb 192.168.1.0/24 -u john.doe -p 'Summer2024!' -M share_audit
```

### Phase 3: Domain Compromise
```bash
# Mit Domain Admin alle Shares prüfen
nxc smb 192.168.0.0/16 -u administrator -p 'DomainP@ss' -d CONTOSO -M share_audit --threads 50
```

### Phase 4: Data Exfiltration Planning
```bash
# Identifizierte Shares mit sensitiven Daten und schlechten Permissions werden priorisiert
nxc smb target-shares.txt -u administrator -p 'P@ss' -M spider_plus --pattern "password|credential|secret"
```

## Reporting-Template

**Finding:** Excessive Share Permissions on Fileserver

```
Host: 192.168.1.10 (FS01.contoso.local)
Share: \\FS01\Finance
Permissions: Everyone - Full Control

Risk:
- Alle Domain User können auf Financial Data zugreifen
- Potenzielle Datenlecks bei Account Compromise
- Compliance-Verstöße (GDPR, SOX)

Evidence:
$ nxc smb 192.168.1.10 -u administrator -p '[REDACTED]' -M share_audit
[!] Share: Finance [Disk]
    [!] Everyone: Full Control (ACCESS_ALLOWED_ACE)

Recommendation:
1. Share-Berechtigung auf "Finance-Team" einschränken
2. Change statt Full Control für normale User
3. NTFS-Berechtigungen zusätzlich restriktiv setzen
4. File Screening für sensitive Dateitypen aktivieren
5. Audit Logging für Share-Zugriffe aktivieren

CVSS: 6.5 (Medium - High depending on data sensitivity)
```

## Troubleshooting Common Issues

### Issue 1: Keine Permissions sichtbar

```bash
# Versuch mit höheren Privilegien
nxc smb target -u Domain-Admin -p 'P@ss' -M share_audit

# Prüfe ob der Account überhaupt Share-Enum Rechte hat
nxc smb target -u user -p 'pass' --shares
```

### Issue 2: Timeout bei großen Netzwerken

```bash
# Threads erhöhen
nxc smb 192.168.1.0/24 -u admin -p 'P@ss' -M share_audit --threads 100

# Oder in kleinere Chunks aufteilen
nxc smb 192.168.1.0/26 -u admin -p 'P@ss' -M share_audit
nxc smb 192.168.1.64/26 -u admin -p 'P@ss' -M share_audit
```

### Issue 3: Module nicht gefunden

```bash
# Modul-Pfad prüfen
ls ~/.nxc/modules/share_audit.py

# Oder direkten Pfad verwenden
nxc smb target -u user -p 'pass' -M ./share_audit.py
```

## Weiterführende Analyse

Nach Identifikation problematischer Shares:

```bash
# 1. Shares browsen
nxc smb target -u admin -p 'pass' --shares

# 2. Dateien listen
smbclient //target/Finance$ -U admin%'pass' -c 'ls'

# 3. Sensitive Files finden
nxc smb target -u admin -p 'pass' -M spider_plus -o READ_ONLY=false

# 4. Dateien herunterladen
smbget -R smb://target/Finance$/Confidential/ -U admin%'pass'
```

## Best Practices

1. **Immer mit Permissions arbeiten** - Pentest sollte autorisiert sein
2. **Logging beachten** - Share-Access wird oft geloggt
3. **Rate Limiting** - Nicht zu aggressiv scannen (IDS/IPS)
4. **Dokumentation** - Screenshots und Logs für Report speichern
5. **Validierung** - Stichproben mit GUI validieren bei kritischen Findings

## Kombination mit PowerShell (falls RDP/WinRM verfügbar)

```powershell
# Auf dem Ziel-Server zur Validierung
Get-SmbShare | Get-SmbShareAccess | Format-Table -AutoSize

# Spezifischer Share
Get-SmbShareAccess -Name "Finance"

# Mit NTFS Permissions vergleichen
Get-SmbShareAccess -Name "Finance"
Get-Acl "C:\Shares\Finance" | Format-List
```
