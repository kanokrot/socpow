# 🔌 Threat Intelligence Sources

## Overview

CABTA (Cyan Agent Blue Team Assistant) integrates with multiple threat-intelligence
and sandbox integrations. This document distinguishes active IOC integrations,
report-only sources, and sandbox paths.

## Current scoring policy

The production IOC scorer uses the six-source admission set and the
AHP-derived source-specific multipliers documented in
[`source_weight_ahp_derivation_2026-09-16.md`](source_weight_ahp_derivation_2026-09-16.md).
VirusTotal remains report-only pending local reliability telemetry.

Exactly six sources currently enter the production IOC-scoring formula:

| Source | Multiplier | Status |
|---|---:|---|
| `feodotracker` | 1.500000 | active |
| `sslblacklist` | 0.878018 | active |
| `spamhaus` | 0.695930 | active |
| `tor_exit_nodes` | 0.542480 | active |
| `c2_trackers` | 0.442818 | active |
| `threatfox` | 0.339610 | active; timeout becomes unavailable and is excluded from that round |

`GROUP_B_EXCLUDE` sources are report-only and do not enter the production
score:

`virustotal`, `abuseipdb`, `shodan`, `alienvault`, `greynoise`, `censys`,
`pulsedive`, `criminalip`, `ipqualityscore`, `phishtank`, `ip2proxy`,
`triage`, and `threatzone`.

More generally, any source not in `NON_API_SCORING_SOURCES` is excluded from
the production score. `GROUP_A_EVAL_SOURCES` is evaluation configuration,
not the production scoring admission list.

An unavailable or stale source is not treated as a clean result. There is no
unknown-source fallback multiplier.

---

## Verified Source Categories

### Admitted IOC scoring sources

These six sources are admitted by `NON_API_SCORING_SOURCES` and
`SOURCE_SCORING_MULTIPLIERS`:

- **FeodoTracker**
- **C2 Trackers**
- **Spamhaus**
- **Tor Exit Nodes**
- **SSL Blacklist**
- **ThreatFox**

### Report-only IOC integrations

The following sources may provide enrichment or reports but are not consumed
by the production IOC-scoring formula:

- VirusTotal
- AbuseIPDB
- Shodan
- AlienVault OTX
- GreyNoise
- Censys
- Pulsedive
- Criminal IP
- IPQualityScore
- PhishTank
- IP2Proxy
- Triage
- ThreatZone

Other implemented IOC integrations, including URLhaus, MalwareBazaar, Talos,
CIRCL, USOM, SMET NRD, and Hagezi NRD, are also report-only because they are
not members of `NON_API_SCORING_SOURCES`.

### Sandbox integrations

Hybrid Analysis, ANY.RUN, and Joe Sandbox use separate sandbox paths.
They are not members of the six-source IOC scoring admission set.

### Not currently implemented as active integrations

SecurityTrails, PassiveTotal, BinaryEdge, OpenPhish, and URLScan are not
currently dispatched by the inspected source-integration code. URLScan is not
used by the application and is omitted from the settings UI.

## Historical Source Categories

The following diagram is retained as historical taxonomy only. It is not an
implementation inventory and must not be used to infer scoring admission.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      THREAT INTELLIGENCE SOURCES                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │   REPUTATION    │  │  THREAT INTEL   │  │   SANDBOXES     │             │
│  │                 │  │                 │  │                 │             │
│  │  • VirusTotal   │  │  • AlienVault   │  │  • Hybrid       │             │
│  │  • AbuseIPDB    │  │  • ThreatFox    │  │  • Triage       │             │
│  │  • IPQuality    │  │  • URLhaus      │  │  • ANY.RUN      │             │
│  │  • GreyNoise    │  │  • MalwareBazaar│  │  • Joe Sandbox  │             │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘             │
│                                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │   PASSIVE DNS   │  │    SCANNING     │  │   PHISHING      │             │
│  │                 │  │                 │  │                 │             │
│  │  • Shodan       │  │  • Censys       │  │  • PhishTank    │             │
│  │  • SecurityTrails│ │  • BinaryEdge   │  │  • OpenPhish    │             │
│  │  • PassiveTotal │  │                 │  │  • URLScan      │             │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Detailed Source Information

### 🔴 VirusTotal

**Type:** Multi-engine antivirus scanning
**IOC Types:** IP, Domain, URL, Hash
**Free Tier:** 500 requests/day
**Production IOC scoring:** Report-only

**What it provides:**
- Antivirus detection results (70+ engines)
- Community votes
- Behavioral analysis
- First/last seen dates

**Get API Key:**
1. Register at https://www.virustotal.com
2. Go to Profile → API Key
3. Copy your key

```yaml
api_keys:
  virustotal: "your-key-here"
```

---

### 🔵 AbuseIPDB

**Type:** IP reputation database
**IOC Types:** IP only
**Free Tier:** 1,000 requests/day
**Production IOC scoring:** Report-only

**What it provides:**
- Abuse confidence score (0-100%)
- Report count
- Last reported date
- ISP/Country information

**Get API Key:**
1. Register at https://www.abuseipdb.com
2. Go to Account → API
3. Generate key

```yaml
api_keys:
  abuseipdb: "your-key-here"
```

---

### 🟢 Shodan

**Type:** Internet scanning/OSINT
**IOC Types:** IP, Domain
**Free Tier:** 100 queries/month
**Production IOC scoring:** Report-only

**What it provides:**
- Open ports
- Running services
- SSL certificates
- Organization info
- Vulnerabilities

**Get API Key:**
1. Register at https://account.shodan.io
2. Go to Account
3. Copy API Key

```yaml
api_keys:
  shodan: "your-key-here"
```

---

### 🟡 AlienVault OTX

**Type:** Open threat exchange
**IOC Types:** IP, Domain, URL, Hash
**Free Tier:** Unlimited
**Production IOC scoring:** Report-only

**What it provides:**
- Pulse (threat report) count
- Pulse details
- Related indicators
- Tags and references

**Get API Key:**
1. Register at https://otx.alienvault.com
2. Go to Settings → API
3. Copy OTX Key

```yaml
api_keys:
  alienvault: "your-key-here"
```

---

### 🟣 GreyNoise

**Type:** Internet scanner detection
**IOC Types:** IP only
**Free Tier:** 50 queries/day
**Production IOC scoring:** Report-only

**What it provides:**
- Is this IP scanning the internet?
- Classification (benign/malicious)
- Actor name (if known)
- Last seen date

**Get API Key:**
1. Register at https://viz.greynoise.io
2. Go to Account → API Key
3. Copy key

```yaml
api_keys:
  greynoise: "your-key-here"
```

---

### 🔶 IPQualityScore

**Type:** Fraud/abuse detection
**IOC Types:** IP, Email, Domain
**Free Tier:** 5,000 requests/month
**Production IOC scoring:** Report-only

**What it provides:**
- Fraud score (0-100)
- Proxy/VPN detection
- Bot detection
- Recent abuse

**Get API Key:**
1. Register at https://www.ipqualityscore.com
2. Go to Settings → API Key
3. Copy key

```yaml
api_keys:
  ipqualityscore: "your-key-here"
```

---

### 🔷 Hybrid Analysis

**Type:** Malware sandbox
**IOC Types:** Hash, URL
**Free Tier:** 100 searches/month
**Production IOC scoring:** Not applicable; separate sandbox path, not part of the IOC scoring formula

**What it provides:**
- Sandbox analysis results
- Threat score
- MITRE ATT&CK mapping
- Network indicators

**Get API Key:**
1. Register at https://www.hybrid-analysis.com
2. Go to Profile → API Key
3. Request API access

```yaml
api_keys:
  hybrid_analysis: "your-key-here"
```

---

### 🔸 Triage (Hatching)

**Type:** Malware sandbox
**IOC Types:** Hash
**Free Tier:** Limited
**Production IOC scoring:** Not applicable; separate sandbox path, not part of the IOC scoring formula

**What it provides:**
- Detailed sandbox analysis
- Malware family identification
- Extracted configurations
- Network IOCs

**Get API Key:**
1. Register at https://tria.ge
2. Go to Account → API
3. Generate key

```yaml
api_keys:
  triage: "your-key-here"
```

---

### Implemented Feed Integrations

These sources have community/free access characteristics; authentication
requirements still vary by source:

| Source | Type | IOC Types | Data |
|--------|------|-----------|------|
| **URLhaus** | Malicious URLs | URL | Malware distribution URLs; report-only |
| **ThreatFox** | IOC Database | IP, Domain, URL, Hash | Auth-Key required; admitted to IOC scoring |
| **MalwareBazaar** | Malware samples | Hash | Sample metadata; report-only |

OpenPhish is not currently dispatched by the IOC integration code.

---

## Example API-Key Configuration

Illustrative API-key settings; this is not a complete integration inventory.

```yaml
api_keys:
  # Essential (highly recommended)
  virustotal: "your-vt-key"
  abuseipdb: "your-abuseipdb-key"
  
  # Recommended
  shodan: "your-shodan-key"
  alienvault: "your-otx-key"
  hybrid_analysis: "your-ha-key"
  
  # Optional (enhanced coverage)
  greynoise: "your-greynoise-key"
  ipqualityscore: "your-ipqs-key"
  triage: "your-triage-key"
  censys: "<api-key>"
  threatfox: "<api-key>"
  anyrun: "<api-key-if-required>"
  joe_sandbox: "<api-key>"
```

### Hybrid Analysis configuration-key compatibility

The current code contains two sandbox paths with different key names:

- `api_keys.hybrid_analysis` is used by `SandboxIntegration`.
- `api_keys.hybridanalysis` is used by the legacy `Sandboxes` path and the
  default environment mapping.

The configuration loader does not normalize these names. Until that code
discrepancy is fixed, configuring only `hybrid_analysis` works for the current
`SandboxIntegration` path but may not enable the legacy path.

---

## Source Reliability & Scoring

The active source multipliers are AHP-derived judgments, not statistically
fitted weights. The full pairwise matrices, source evidence, priority vectors,
and consistency ratios are in
[`source_weight_ahp_derivation_2026-09-16.md`](source_weight_ahp_derivation_2026-09-16.md).

ThreatFox is admitted based on 720/720 successful historical telemetry rows,
documented confirmed/vetted submission requirements, and a six-month expiry
policy. Two of those 720 rows exceeded the current 15-second production
deadline (`0.277778%`; both URL records). A ThreatFox timeout is marked
unavailable, is not retried, does not block the pipeline, is excluded from the
round's score, and is never interpreted as clean.

VirusTotal remains report-only. The application currently defines a local
limit of 4 requests/minute. Provider plan limits and daily quotas must be
verified against current provider documentation. Its AHP multiplier is
retained for auditability only and is not used in production scoring.

---

## Rate Limits & Best Practices

### Handling Rate Limits

The current scoring path uses the feed-only admission policy described above.
ThreatFox is the API-key-backed exception admitted to scoring: it has a
15-second per-source deadline, and a timeout is marked unavailable, is not
retried, does not block the pipeline, and is excluded from that round's score.
Unavailable is never interpreted as clean. VirusTotal and other API/query
sources remain report-only; their rate limits are constraints on reporting,
not scoring multipliers.

### Best Practices

1. **Verify Provider Quotas**: Free tiers, quotas, and eligibility vary by
   provider and plan; do not assume that every source has a sufficient free tier.

2. **Prioritize Sources by the Active Policy**:
   - Feed-only sources contribute to production scoring using the AHP-derived
     multipliers in the current scoring policy.
   - VirusTotal and other API/query sources can provide supplemental reports,
     but do not contribute to the production score.

3. **Cache Results**: For bulk analysis, consider implementing caching to avoid repeated API calls.

4. **Monitor Usage**: Track your API usage to avoid hitting limits during investigations.

---

## Troubleshooting

### "No API key configured"
```
Source returns: "No valid API key configured"
```
**Solution:** Add the API key to config.yaml

### "Rate limit exceeded"
```
Source returns: "HTTP 429" or "Rate limit"
```
**Solution:** For report-only sources, respect the provider's documented quota
or wait before a separate report query. ThreatFox scoring does not retry after
a timeout.

### "Timeout"
```
Source returns: "Timeout after 15s"
```
**Solution:** The affected source is marked unavailable and skipped for this
scoring round; it is not treated as clean and is not retried for ThreatFox.

### "Error"
```
Source returns: "Error"
```
**Solution:** Check API key validity or API status page
