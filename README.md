# NetExec Share Audit Module

Ein NetExec-Modul zum Auslesen von SMB-Share-Berechtigungen während Penetrationstests.

## Disclaimer

This thing is totally vibe-coded, and I'm not ashamed about it.

## Zweck

Dieses Modul hilft Pentestern dabei, schnell zu identifizieren welche Netzwerkfreigaben zu weitreichende Berechtigungen haben. Es zeigt nicht nur die Shares, sondern auch die **Freigabeberechtigungen** (Share ACLs), was bei der Bewertung von Sicherheitsrisiken entscheidend ist.

### Use Case

In Pentests findet man häufig sensitive Daten in Netzwerkfreigaben. Es macht einen großen Unterschied ob eine Freigabe mit sensitiven Daten:
- Für eine kleine AD-Gruppe mit 4 Benutzern freigegeben ist ✅
- Oder für "Jeder - Vollzugriff" konfiguriert ist ⚠️

Nach dem Erlangen von Domain Admin Rechten kann man mit diesem Modul schnell das gesamte Netzwerk scannen.

## Features

- ✅ Listet alle SMB-Shares auf Remote-Hosts auf
- ✅ Zeigt Freigabeberechtigungen (Share Permissions) an
- ✅ Übersetzt SIDs zu lesbaren Namen (Everyone, Authenticated Users, etc.)
- ✅ Übersetzt Access Masks zu verständlichen Rechten (Full Control, Change, Read)
- ✅ Hebt gefährliche Konfigurationen hervor ("Everyone - Full Control", etc.)
- ✅ Funktioniert über SMB/RPC (kein WinRM erforderlich)
- ✅ Unterstützt Authentifizierung mit Username/Password oder Hash

## Installation

1. **Modul in NetExec Module-Verzeichnis kopieren:**

```bash
# Linux/MacOS
cp share_audit.py ~/.nxc/modules/

# Windows
copy share_audit.py %USERPROFILE%\.nxc\modules\
```

2. **Alternativ: Lokales Modul verwenden:**

NetExec kann Module auch aus dem aktuellen Verzeichnis laden:

```bash
nxc smb <target> -u <user> -p <pass> -M ./share_audit.py
```

## Verwendung

### Basis-Scan eines einzelnen Hosts:

```bash
nxc smb 192.168.1.10 -u administrator -p 'P@ssw0rd' -M share_audit
```

### Netzwerk-Scan:

```bash
nxc smb 192.168.1.0/24 -u administrator -p 'P@ssw0rd' -M share_audit
```

### Mit NTLM-Hash (Pass-the-Hash):

```bash
nxc smb 192.168.1.10 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0' -M share_audit
```

### Mit Domain-Credentials:

```bash
nxc smb 192.168.1.10 -u administrator -p 'P@ssw0rd' -d CONTOSO -M share_audit
```

### Detaillierte Ausgabe (Optional):

```bash
nxc smb 192.168.1.10 -u administrator -p 'P@ssw0rd' -M share_audit -o DETAILED=true
```

## Output-Beispiel

```
SMB         192.168.1.10    445    DC01    [*] Windows Server 2019 (name:DC01) (domain:contoso.local)
SMB         192.168.1.10    445    DC01    [+] contoso.local\administrator:P@ssw0rd (Pwn3d!)
SHARE_AUD   192.168.1.10    445    DC01    [*] Starting share permissions audit
SHARE_AUD   192.168.1.10    445    DC01    [+] Found 5 share(s)
SHARE_AUD   192.168.1.10    445    DC01    [!] Share: Finance [Disk]
SHARE_AUD   192.168.1.10    445    DC01      Comment: Financial Documents
SHARE_AUD   192.168.1.10    445    DC01      Permissions:
SHARE_AUD   192.168.1.10    445    DC01        [!] Everyone: Full Control (ACCESS_ALLOWED_ACE)
SHARE_AUD   192.168.1.10    445    DC01    [*] Share: IT [Disk]
SHARE_AUD   192.168.1.10    445    DC01      Permissions:
SHARE_AUD   192.168.1.10    445    DC01        - Administrators: Full Control (ACCESS_ALLOWED_ACE)
SHARE_AUD   192.168.1.10    445    DC01        - IT-Team: Change (ACCESS_ALLOWED_ACE)
```

## Was wird überprüft?

### Share Permissions vs. NTFS Permissions

⚠️ **Wichtig:** Dieses Modul zeigt die **Freigabeberechtigungen** (Share Permissions), nicht die NTFS-Berechtigungen.

Die effektiven Berechtigungen sind die **restriktivsten** der beiden:
- Share Permission: Everyone - Full Control
- NTFS Permission: Domain Users - Read

→ Effektiv: Domain Users - Read

Dennoch ist "Everyone - Full Control" auf Share-Ebene ein Security-Finding, da es die Angriffsfläche unnötig vergrößert.

## Erkannte Berechtigungen

Das Modul erkennt und übersetzt folgende Berechtigungen:

- **Full Control** (0x001F01FF): Voller Zugriff
- **Change** (0x001301BF): Lesen, Schreiben, Löschen
- **Read** (0x001200A9): Nur Lesen
- **Custom**: Individuelle Rechtekombinationen

## Erkannte Trustees

Bekannte SIDs werden automatisch übersetzt:

- `S-1-1-0` → Everyone
- `S-1-5-7` → Anonymous
- `S-1-5-11` → Authenticated Users
- `S-1-5-32-544` → Administrators
- `S-1-5-32-545` → Users
- Und weitere...

## Gefährliche Konfigurationen

Das Modul hebt automatisch gefährliche Konfigurationen hervor:

- ⚠️ Everyone mit Full Control oder Change
- ⚠️ Anonymous mit beliebigen Rechten
- ⚠️ Guests mit Schreibrechten

## Technische Details

- **Protokoll**: SMB über RPC (MSRPC_UUID_SRVS)
- **API Calls**:
  - `NetShareEnum` (Level 1) - Shares auflisten
  - `NetShareGetInfo` (Level 502) - Security Descriptor abrufen
- **Bibliothek**: impacket
- **Authentifizierung**: Username/Password oder NTLM-Hash

## Voraussetzungen

- NetExec (nxc) installiert
- impacket Bibliothek (wird normalerweise mit NetExec installiert)
- Gültige Domain-Credentials mit mindestens Read-Rechten

## Troubleshooting

### "Access Denied" für bestimmte Shares

Manche Shares können nur von bestimmten Gruppen gelesen werden. Das Modul zeigt dann "ACCESS DENIED" an.

### Modul wird nicht gefunden

Stelle sicher, dass das Modul im korrekten Verzeichnis liegt:

```bash
# Modulverzeichnis prüfen
ls -la ~/.nxc/modules/

# Oder Modul direkt mit Pfad laden
nxc smb <target> -u <user> -p <pass> -M ./share_audit.py
```

### RPC Verbindungsfehler

Stelle sicher, dass:
- Port 445 (SMB) erreichbar ist
- Die Credentials korrekt sind
- Der Zielhost online ist

## Reporting-Tipps für Pentests

Bei der Dokumentation von Findings:

1. **Screenshot/Befehlsausgabe** des nxc-Scans
2. **Kontext**: Welche sensitiven Daten wurden auf dem Share gefunden?
3. **Risiko**: Wie viele User gehören zur berechtigten Gruppe?
4. **Empfehlung**: Least Privilege Prinzip - nur notwendige Berechtigungen
5. **CVSS/Schweregrad**: Abhängig von den Daten und der Exposition

## Beispiel-Finding

```
Title: Sensitive Share mit zu weitreichenden Berechtigungen

Share: \\DC01\Finance
Permissions: Everyone - Full Control
Inhalt: Gehaltslisten, Finanzdaten
Risiko: Alle Domain-User können auf sensitive Finanzdaten zugreifen

Empfehlung:
- Share-Berechtigung auf "Finance-Team - Change" einschränken
- NTFS-Berechtigungen zusätzlich restriktiv setzen
- Sensitive Daten in separaten Ordnern mit Encryption ablegen
```

## License

MIT - Free to use for Penetration Testing and Security Audits

## Autor

Created for the Offensive Security Community

## Disclaimer

This tool is for authorized security testing only. Only use on systems you have explicit permission to test.
