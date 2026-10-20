# 📖 User Manual

## Table of Contents
- [Login & Roles](#login--roles)
- [IOC Investigation](#ioc-investigation)
- [Malware Analysis](#malware-analysis)
- [Email Analysis](#email-analysis)
- [Web UI](#web-ui)
- [Agent / Local Tool](#agent--local-tool)
- [Report Generation](#report-generation)
- [MCP Server Mode](#mcp-server-mode)
- [Batch Processing](#batch-processing)

---

## Login & Roles

### Roles

The application defines these roles:

- `SOC Analyst Tier 1-2`
- `Incident Responder`
- `Threat Hunter`
- `admin`
- `Team Lead`

### Login and session security

Login accepts either a username or an email address, together with a
password. A successful login creates an access token and sets the
`socpow_session` session cookie and `socpow_csrf` CSRF cookie. Cookie-authenticated
unsafe requests (`POST`, `PUT`, `PATCH`, and `DELETE`) must send an
`X-CSRF-Token` header matching the CSRF cookie. The cookies use `SameSite=Strict`.
Failed login attempts are rate-limited.

### Default landing page by role

After login, `ROLE_DEFAULT_LANDING` returns the following default path:

| Role | Default path |
|---|---|
| `SOC Analyst Tier 1-2` | `/analysis/ioc` |
| `Incident Responder` | `/agent/playbooks` |
| `Threat Hunter` | `/` |
| `Team Lead` | `/dashboard` |
| `admin` | `/` |

### Team Lead invites

A Team Lead can invite a team member through the team-member invite endpoint.
The flow is invite-based: the server creates a one-time invite token, and the
recipient completes the invitation through `/api/auth/accept-invite` with the
token, username, and password. Team Leads may invite operator roles only; this
is not self-registration or role selection by the recipient.

### Requesting access

Users can submit an access request at `/request-access` with the page's GET/POST
flow. Pending requests are stored and can be listed, approved, or rejected.
The `/management` page renders the pending access-request queue.

### Per-user Gmail OAuth

Link or unlink Gmail from the authenticated Account page at `/account`. Gmail
connect, status, and disconnect operations are bound to the authenticated user.
OAuth state and tokens are persisted by `user_id`. The callback URI is
`http://localhost:3003/api/settings/gmail/callback`.

### Per-user threat intelligence API keys

Authenticated users can add or remove their own VirusTotal, AbuseIPDB, and
AlienVault OTX API keys from `/account`. These keys run optional cross-checks
after an IOC investigation and appear as “Extra, non-scoring evidence”; they
do not affect the investigation score, verdict, or source coverage. Keys are
encrypted at rest and are never returned by the key management API.

---

## IOC Investigation

### Basic Usage

```bash
# Investigate an IP address
python -m src.soc_agent ioc 192.168.1.100

# Investigate a domain
python -m src.soc_agent ioc evil-domain.com

# Investigate a URL
python -m src.soc_agent ioc "https://malicious-site.com/payload.exe"

# Investigate a file hash
python -m src.soc_agent ioc d41d8cd98f00b204e9800998ecf8427e
```

### With HTML Report

```bash
python -m src.soc_agent ioc 185.199.108.153 --report ip_investigation.html
```

### Understanding Results

The example below is schematic. The production IOC score uses these six
sources: FeodoTracker, SSL Blacklist, Spamhaus, Tor Exit Nodes, C2 Trackers,
and ThreatFox. VirusTotal, AbuseIPDB, Shodan, and AlienVault OTX may appear
as optional cross-checks, but they do not affect score, verdict, or coverage.

```
═══════════════════════════════════════════════════════════════════════════════
                         SOCPOW - IOC INVESTIGATION
═══════════════════════════════════════════════════════════════════════════════

 IOC: 185.199.108.153
 Type: IPv4                          ← Automatically detected type
 Verdict: SUSPICIOUS (Score: 45/100) ← Overall verdict with score

┌─ IOC SCORING SOURCES               ← Sources admitted to the score
│
│  FeodoTracker    : <result or status>
│  SSL Blacklist   : <result or status>
│  Spamhaus        : <result or status>
│  Tor Exit Nodes  : <result or status>
│  C2 Trackers     : <result or status>
│  ThreatFox       : <result or unavailable>
│
│  Source coverage: <covered>/<eligible>
│  Score is a formula output, not a probability.
└─────────────────────────────────────────────────────────────────────────────

┌─ OPTIONAL, NON-SCORING CROSS-CHECKS
│
│  VirusTotal      : <detections, when configured>
│  AbuseIPDB       : <confidence, when configured>
│  Shodan          : <enrichment, when configured>
│  AlienVault OTX  : <reports, when configured>
└─────────────────────────────────────────────────────────────────────────────

┌─ DETECTION RULES                    ← Auto-generated rules
│
│  KQL Query:
│  DeviceNetworkEvents
│  | where RemoteIP == "185.199.108.153"
│  | project Timestamp, DeviceName, InitiatingProcessFileName
│
│  SIGMA Rule: [Copy button available in HTML report]
└─────────────────────────────────────────────────────────────────────────────

┌─ RECOMMENDATIONS                    ← Actionable next steps
│
│  • Monitor network traffic to this IP
│  • Check historical connections in SIEM
│  • Consider adding to watchlist
└─────────────────────────────────────────────────────────────────────────────
```

### Verdict Interpretation

| Score | Verdict | Action |
|-------|---------|--------|
| 0-39 | CLEAN | No action required |
| 40-69 | SUSPICIOUS | Monitor and investigate further |
| 70-100 | MALICIOUS | Block and investigate |
| Any score | UNKNOWN | Source coverage is insufficient |

These scores are signals from the scoring formula, not probabilities. The
application may return `UNKNOWN` when the covered source ratio is below 30%.
However, a score of at least 70 with at least one flagged source remains
`MALICIOUS` even when coverage is low. An unavailable source is not treated as
a clean result. In particular, ThreatFox timeouts are recorded as unavailable
and excluded from that round's score.

---

## Malware Analysis

### Basic Usage

```bash
# Analyze a Windows executable
python -m src.soc_agent file suspicious.exe

# Analyze a DLL
python -m src.soc_agent file malware.dll

# Analyze an Office document
python -m src.soc_agent file macro_doc.docm

# Analyze a PDF
python -m src.soc_agent file evil.pdf

# Analyze a script
python -m src.soc_agent file payload.ps1
```

### With HTML Report

```bash
python -m src.soc_agent file suspicious.exe --report analysis_report.html
```

### Understanding Results

```
═══════════════════════════════════════════════════════════════════════════════
                    BLUE TEAM ASSISTANT - MALWARE ANALYSIS
═══════════════════════════════════════════════════════════════════════════════

 SECTION 1: FILE OVERVIEW
┌─────────────────────────────────────────────────────────────────────────────
│  File Name       : suspicious.exe
│  File Size       : 1.85 MB
│  File Type       : PE32 executable (GUI) Intel 80386
│  
│  Hashes:
│  ├── MD5         : d41d8cd98f00b204e9800998ecf8427e
│  ├── SHA1        : da39a3ee5e6b4b0d3255bfef95601890afd80709
│  └── SHA256      : e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
│
│  Verdict         : 🔴 MALICIOUS (Score: 87/100)
│  First Seen      : 2024-01-15 (VirusTotal)
└─────────────────────────────────────────────────────────────────────────────

 SECTION 2: THREAT INTELLIGENCE
┌─────────────────────────────────────────────────────────────────────────────
│  VirusTotal      : 45/72 detections
│  │ └── Top detections: Trojan.GenericKD, Malware.Emotet, Win32.Packed
│  
│  Hybrid Analysis : Threat Score 100/100
│  │ └── Family: Emotet | Verdict: malicious
│  
│  MalwareBazaar   : Found
│  │ └── Tags: Emotet, Trojan, Loader
│  
│  Triage          : Found
│  │ └── Sandbox score: 10/10
│  
│  Sources Checked : 8
│  Sources Flagged : 6
└─────────────────────────────────────────────────────────────────────────────

 SECTION 3: STATIC ANALYSIS
┌─────────────────────────────────────────────────────────────────────────────
│  PE Header
│  ├── Architecture    : x86 (32-bit)
│  ├── Compile Time    : 2024-01-10 08:23:45
│  ├── Entry Point     : 0x00012340
│  ├── Subsystem       : Windows GUI
│  └── Security        : ASLR: ✅ | DEP: ✅ | CFG: ❌
│
│  Entropy Analysis
│  ├── Overall         : 7.89/8.00
│  ├── Interpretation  : 🔴 Packed/Encrypted
│  └── Sections:
│      ├── .text       : 6.21 (normal)
│      ├── .data       : 4.85 (normal)
│      ├── .rsrc       : 7.95 (HIGH - encrypted)
│      └── .reloc      : 7.88 (HIGH - packed)
│
│  Suspicious Imports (12 found)
│  ├── VirtualAllocEx     → Process Injection
│  ├── WriteProcessMemory → Process Injection  
│  ├── CreateRemoteThread → Process Injection
│  ├── NtUnmapViewOfSection → Process Hollowing
│  ├── InternetOpenUrlA   → Network Activity
│  └── ... 7 more
│
│  Suspicious Strings (8 found)
│  ├── "cmd.exe /c"        → Command execution
│  ├── "powershell -enc"   → Encoded PowerShell
│  ├── "HKEY_CURRENT_USER" → Registry access
│  └── ... 5 more
└─────────────────────────────────────────────────────────────────────────────

 SECTION 4: MITRE ATT&CK MAPPING
┌─────────────────────────────────────────────────────────────────────────────
│  🔴 T1055 : Process Injection
│     └─ Tactic: Defense Evasion, Privilege Escalation
│
│  🔴 T1059.001 : PowerShell
│     └─ Tactic: Execution
│
│  🟡 T1082 : System Information Discovery
│     └─ Tactic: Discovery
│
│  🟡 T1547.001 : Registry Run Keys
│     └─ Tactic: Persistence
│
│  Total Techniques: 12
│  Navigator Export: analysis_navigator.json
└─────────────────────────────────────────────────────────────────────────────

 SECTION 5: DETECTION RULES
┌─────────────────────────────────────────────────────────────────────────────
│  YARA Rule:
│  rule suspicious_exe_d41d8cd9 {
│      meta:
│          description = "Detects suspicious.exe"
│          author = "Ugur Ates"
│          hash = "e3b0c44298fc1c149..."
│      strings:
│          $s1 = "VirtualAllocEx"
│          $s2 = "WriteProcessMemory"
│      condition:
│          uint16(0) == 0x5A4D and all of them
│  }
│
│  KQL Query:
│  DeviceFileEvents
│  | where SHA256 == "e3b0c44298fc1c149afbf4c8996fb924..."
│  | project Timestamp, DeviceName, FileName, FolderPath
└─────────────────────────────────────────────────────────────────────────────
```

### Entropy Interpretation

| Range | Interpretation | Implication |
|-------|----------------|-------------|
| 0.0 - 1.0 | Empty/Sparse | Null bytes, minimal content |
| 1.0 - 4.5 | Plain text | Source code, documents |
| 4.5 - 6.5 | Normal executable | Standard compiled code |
| 6.5 - 7.2 | Compressed | UPX, standard packers |
| 7.2 - 7.8 | Packed | Custom packers, protectors |
| 7.8 - 8.0 | Encrypted | Crypters, ransomware payloads |

---

## Email Analysis

### Basic Usage

```bash
# Analyze an EML file
python -m src.soc_agent email suspicious.eml

# Analyze with HTML report
python -m src.soc_agent email phishing.eml --report email_report.html
```

### Understanding Results

```
═══════════════════════════════════════════════════════════════════════════════
                    BLUE TEAM ASSISTANT - EMAIL ANALYSIS
═══════════════════════════════════════════════════════════════════════════════

 SECTION 1: EMAIL OVERVIEW
┌─────────────────────────────────────────────────────────────────────────────
│  Subject         : Urgent: Your account has been compromised!
│  From            : security@micros0ft.com ← Note: typosquatting!
│  To              : victim@company.com
│  Date            : 2024-01-15 10:23:45
│
│  Verdict         : 🔴 PHISHING (Score: 92/100)
└─────────────────────────────────────────────────────────────────────────────

 SECTION 2: AUTHENTICATION RESULTS
┌─────────────────────────────────────────────────────────────────────────────
│  SPF             : ❌ FAIL (sender not authorized)
│  DKIM            : ❌ FAIL (signature invalid)
│  DMARC           : ❌ FAIL (policy: reject)
│
│  🔴 All authentication checks failed - high confidence phishing
└─────────────────────────────────────────────────────────────────────────────

 SECTION 3: PHISHING INDICATORS
┌─────────────────────────────────────────────────────────────────────────────
│  ⚠️  Domain Spoofing
│      └── micros0ft.com looks like microsoft.com (typosquatting)
│
│  ⚠️  Urgency Keywords
│      └── "Urgent", "immediately", "suspended"
│
│  ⚠️  Suspicious Links
│      └── Display text: "Click here to verify"
│          Actual URL: http://evil-site.com/steal-creds.php
│
│  ⚠️  Sender Mismatch
│      └── From header doesn't match Return-Path
└─────────────────────────────────────────────────────────────────────────────

 SECTION 4: EXTRACTED IOCs
┌─────────────────────────────────────────────────────────────────────────────
│  URLs (3):
│  ├── http://evil-site.com/steal-creds.php (MALICIOUS)
│  ├── http://tracking.malware.com/1x1.gif (SUSPICIOUS)
│  └── https://legitimate-link.com (CLEAN)
│
│  Domains (2):
│  ├── evil-site.com (newly registered; no reputation — age alone does not raise the score)
│  └── tracking.malware.com (known malware host)
│
│  IPs (1):
│  └── 192.168.100.50 (hosting evil-site.com)
└─────────────────────────────────────────────────────────────────────────────

 SECTION 5: ATTACHMENTS
┌─────────────────────────────────────────────────────────────────────────────
│  invoice.pdf (45 KB)
│  ├── Type: PDF
│  ├── Contains: JavaScript
│  └── Verdict: 🔴 MALICIOUS (embedded JS downloader)
└─────────────────────────────────────────────────────────────────────────────
```

---

## Web UI

### Agent

Open `/agent/chat` for the Agent chat page or `/agent/investigations` for the
investigations page. The Agent API is under `/api/agent`: it starts an
investigation, lists and loads sessions, and handles approval, rejection, and
cancellation. The pages use `templates/agent_chat.html` and
`templates/agent_investigations.html`; the investigations template includes the
start form and API call.

Evidence: `src/web/routes/agent.py:62-78`, `:184-228`, `:233-292`;
`src/web/app.py:708-719`; `templates/agent_chat.html`,
`templates/agent_investigations.html:845-865`, `:2614-2644`.

### Playbooks

Open `/agent/playbooks`. The Playbooks API is under `/api/playbooks`: it lists
playbooks, shows details, runs a playbook, approves or rejects a pending step,
and generates a session report. The page is rendered by
`templates/playbooks.html`.

Evidence: `src/web/routes/playbooks.py:35-88`, `:96-131`, `:134-179`;
`src/web/app.py:723-731`; `templates/playbooks.html:430-578`, `:976-1043`.

### Cases

Use `/cases` for the case list and `/cases/{case_id}` for a case detail page.
The Cases API is under `/api/cases`: it creates, lists, and displays cases;
handles incident reports; updates routing and status; links analyses; and adds
notes. The pages use `templates/cases.html` and `templates/case_detail.html`.

Evidence: `src/web/routes/cases.py:37-72`, `:79-137`, `:143-225`;
`src/web/app.py:654-667`; `templates/cases.html:2-14` and
`templates/case_detail.html:2-7`, `:231-321`.

### Tickets

Open `/tickets` to view authenticated, owner-scoped tickets. The ticket page
identifies auto-generated incident tickets and displays their status. The page
uses `templates/tickets.html` and the API route is under the `/api` prefix.

Evidence: `src/web/routes/tickets.py:16-25`; `src/web/app.py:670-695`;
`templates/tickets.html:2-19`, `:29-56`.

### Help Desk (SOC Room)

The **SOC Room** page (`/soc-operations`) is the system's help desk. Any logged-in
user can open it. The pixel office is decorative; the panel on the right is where
you read answers and send feedback.

**Answers tab**
- Search the frequently asked questions by keyword.
- Select a question to open its answer; only one answer is open at a time.
- If nothing matches, choose **Report it instead**. The report form opens with your
  search term already in the message.

**Report a finding**
1. Choose a type: **Wrong verdict**, **Something is broken**, or **Idea or other**.
2. Optional: add a reference (an analysis ID or page name, up to 200 characters).
3. Describe what you saw and what you expected (at least 5 and at most 2000 characters).
4. Select **Send report**. A reference ID is shown once it is saved.

Each account can send up to 20 reports per hour. Only the `admin` role can read
them; Team Lead and the other roles cannot.

**Admin: Help Desk admin page** (`/admin/helpdesk`, admin role only)
- **Inbox**: reports from users, newest first, with filters for New, Reviewed and
  Resolved. Update a report's status and add an admin-only note (up to 2,000 characters).
- **FAQ editor**: add, edit, delete and set the sort order of the FAQ entries shown
  on the Answers tab. A question can be up to 300 characters and an answer up to
  4,000. Use the inbox to find questions that keep coming back.

### MCP Management

Open `/mcp/servers` to configure and manage MCP server connections. The MCP
Management API is under `/api/mcp`: it lists categories and servers, adds and
removes servers, connects and disconnects them, lists server tools, and checks
availability. The page is rendered by `templates/mcp_servers.html`.

Evidence: `src/web/routes/mcp_management.py:271-333`, `:348-478`;
`src/web/app.py:734-750`; `templates/mcp_servers.html:218-226`, `:300-433`,
`:808-951`.

### Reports — Web UI/API

Open `/report/{job_id}` for the report view. The Reports API is under
`/api/reports` and serves JSON, HTML, HTML downloads, MITRE output, and PDF.
It also supports editing, approving, marking detection rules as deployed,
downloading rules, and exporting detection rules as a ZIP. The page is rendered
by `templates/report_view.html`.

Evidence: `src/web/app.py:697-705`; `src/web/routes/reports.py:179-275`,
`:279-475`; `templates/report_view.html:206`, `:218-253`, `:1378-1550`.

The CLI report-generation instructions remain in [Report Generation](#report-generation).

---

## Agent / Local Tool

`generate_rules` is a local Agent tool. Its executor is defined at
`src/agent/tool_registry.py:613-640`, and the local tool is registered at
`src/agent/tool_registry.py:848-899`.

The registered tool accepts `analysis_result`, `rule_type`, `rule_types`, and
`network_iocs`. It is not one of the tools exposed by the legacy
`python -m src.server` MCP server.

---

## Report Generation

### HTML Reports

```bash
# Generate HTML report for any analysis
python -m src.soc_agent ioc 8.8.8.8 --report ioc_report.html
python -m src.soc_agent file malware.exe --report file_report.html
python -m src.soc_agent email phish.eml --report email_report.html
```

### HTML Report Features

- **Interactive**: Collapsible sections, tabs
- **Downloadable**: Detection rules, IOC lists
- **Visual**: Charts, color-coded verdicts
- **Shareable**: Self-contained single file

### Additional File Exports

The CLI currently supports human-readable output and HTML reports through
`--report`. It does not define a `--format json` argument.

For file analysis, the following optional exports are available:

```bash
python -m src.soc_agent file sample.exe --pdf executive.pdf
python -m src.soc_agent file sample.exe --timeline timeline.html
python -m src.soc_agent file sample.exe --navigator mitre_layer.json
python -m src.soc_agent file sample.exe --sandbox
```

---

## MCP Server Mode

Blue Team Assistant can run as an MCP (Model Context Protocol) server for integration with Claude Desktop or other MCP clients.

### Remote Host MCP Server

Remote Host is provided by the separate `src.mcp_servers.remote_tools` MCP
server; it is not a Web UI feature. It exposes these five tools:
`system_info_collect`, `process_list_collect`, `netstat_collect`,
`event_log_collect`, and `autoruns_check`.

Before use, configure the `remote_hosts` allowlist in `config.yaml` with the
approved host, SSH key, and dedicated `known_hosts` file. The example default
is `remote_hosts: []`, so no host is allowed by default.

### Starting the Server

```bash
python -m src.server
```

### Available Tools

| Tool | Description |
|------|-------------|
| `investigate_ioc` | Investigate an IOC |
| `analyze_file` | Analyze a file |
| `analyze_email` | Analyze an email |

### Claude Desktop Configuration

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "blue-team-assistant": {
      "command": "python",
      "args": ["-m", "src.server"],
      "cwd": "/path/to/blue-team-assistant"
    }
  }
}
```

---

## Batch Processing

### Process Multiple IOCs

```bash
# From a file (one IOC per line)
while read ioc; do
    python -m src.soc_agent ioc "$ioc" >> results.txt
done < iocs.txt

# Using xargs
cat iocs.txt | xargs -I {} python -m src.soc_agent ioc {}
```

### Process Multiple Files

```bash
# Analyze all EXE files in a directory
for file in /path/to/samples/*.exe; do
    python -m src.soc_agent file "$file" --report "reports/$(basename $file).html"
done
```

### PowerShell Batch Processing

```powershell
# Analyze multiple files
Get-ChildItem -Path .\samples\*.exe | ForEach-Object {
    python -m src.soc_agent file $_.FullName --report "reports\$($_.BaseName).html"
}
```

---

## Tips & Best Practices

### 1. Use HTML Reports for Sharing
HTML reports are self-contained and can be shared with non-technical stakeholders.

### 2. Check Configuration
Review `config.yaml` for the integrations you intend to use. To inspect the
available CLI commands:

```bash
python -m src.soc_agent --help
```

### 3. Interpret Scores in Context
A score of 50 doesn't mean "50% malicious" - it means multiple signals indicate suspicion. Always review the detailed findings.

### 4. Use Detection Rules
Copy the auto-generated YARA/SIGMA/KQL rules to your security tools for proactive detection.

### 5. Trust the FP Reduction
If the tool marks something as CLEAN despite being extracted from a suspicious file, it's likely legitimate infrastructure (DigiCert, Microsoft, etc.).
