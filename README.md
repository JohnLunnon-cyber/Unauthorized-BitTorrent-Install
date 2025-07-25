# ⚠️ Unauthorized BitTorrent Installation

## ✅ STEP 1 — Initial Detection

### 🔎 Scenario
Unauthorized installation of BitTorrent software on a corporate endpoint.

### 💻 Environment
- Onboarded VM: `john-target1-vm`

### 🛠️ Tools Used
- Microsoft Defender for Endpoint (MDE)
- KQL (Kusto Query Language)

### 📂 KQL File Detection
```kql
DeviceFileEvents
| where FileName has "bittorrent"
| where ActionType in ("FileCreated", "FileDownloaded")
| order by Timestamp desc
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FileName, FolderPath, SHA256
```

---

## 🚨 Incident Report: Unauthorized BitTorrent Installation

### 🗓️ Date/Time
**20 July 2025**, between **11:09:48** and **11:10:30 UTC**

### 👤 User
**cyberuser**

### 💻 Device
**john-target1-vm**

### 🔍 Key Timeline of Events
- Temporary installer files created
- BitTorrent installed in `AppData\Roaming\bittorrent\`
- Shortcuts (.lnk) created on Desktop, Start Menu, Quick Launch
- Application ran without admin elevation (runs under standard user)

### 🧠 Analysis
- Installer activity began in temp directories (typical for downloads)
- User account created shortcuts for easy access
- Install ran silently using typical flags
- Likely bypassed admin due to install in roaming profile

---

## ✅ STEP 2 — Execution Evidence

### 🔍 KQL: Check for Process Execution
```kql
DeviceProcessEvents
| where FileName has "bittorrent"
| order by Timestamp desc
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine
```

### 📋 Summary of Process Execution
- Installer executed **twice**
- BitTorrent launched at **11:22:35**
- Silent install switches used: `/S`, `/FORCECLOSEAPPLICATIONS`

---

## ❌ STEP 3 — Incident Summary

### ⌛ Detection Timeframe
- **Start**: 20 July 2025, 11:10:00 UTC  
- **End**: 20 July 2025, 11:24:38 UTC

### 📅 Affected Asset
- VM: `john-target1-vm`
- User: `cyberuser`

### 🔍 Key Findings
- BitTorrent installer files:
  - `bittorrent_installer.tmp`
  - `bittorrent_installer.exe`
- Silent command observed:
```plaintext
"BitTorrent.exe" /S /FORCEINSTALL 1110010101111110
```
- Outbound connections to known BitTorrent IPs:
  - `3.233.196.30`
  - `82.221.103.246`
  - `104.16.213.94`
  - `18.160.41.97`
  - `54.173.189.12`
- Frequent connection spikes: P2P swarm behavior

### 📉 Risk Assessment
- High: Potential data exfiltration, remote connections, unmonitored traffic

---

## ⛨️ STEP 4 — Network Connections Observed

BitTorrent made outbound network calls:

- **IPs Contacted:**
  - `82.221.103.246` *(Iceland, suspected peer/tracker)*
  - `18.160.41.97` *(Amazon AWS)*

- **Protocol/Port:** TCP 443

### 🧠 Implications
- Active peer communication
- Encrypted traffic (harder to inspect)
- Possible exposure to:
  - Malicious peers
  - Data exfiltration
  - Policy violations

---

## 🖊️ Investigation Conclusion: BitTorrent Installation on `john-target1-vm`

### 🔍 Summary of Findings
- **BitTorrent.exe** installed by user `cyberuser`
- Multiple `.lnk` shortcut files confirm user intent
- **Files created:** Executable, temp files, shortcuts
- **Network connections:**
  - `82.221.103.246` (tracker/peer)
  - `18.160.41.97` (Amazon AWS)
- **All traffic over TCP 443** (likely encrypted)

### 📉 Risk Assessment
P2P software increases:
- Exposure to unknown systems
- Data loss risks
- Inspection difficulty due to encryption
- Compliance and legal concerns

---

## ✅ Conclusion & Recommendations

The investigation confirms:
- BitTorrent was **downloaded, installed, and executed**
- External connections were made
- No elevation was required (executed as user)

### ✅ Response Actions:
- ❌ **Block BitTorrent.exe** via Microsoft Defender for Endpoint
- 🔐 **Apply Application Control Policies** to prevent future installations
- 🤝 **Educate end users** on the risks of P2P software
- 📄 **Close the case** with status: `Non-Malicious Policy Violation`

---
