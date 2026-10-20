import asyncio
import aiohttp
import re
import json
from typing import Dict, Optional
from src.integrations.verdict_validator import validate_llm_analysis
import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# [GUARDRAIL ADDITION] รายชื่อ Threat Intel source ทั้งหมดที่ SOCPOW เช็ค
# ใช้สำหรับตรวจจับว่า LLM พูดถึง source ที่ไม่ได้อยู่ใน verified findings หรือไม่
# (ป้องกัน hallucination ที่หลุดผ่าน prompt-level guardrail)
# ---------------------------------------------------------------------------
ALL_TI_SOURCES = [
    'virustotal', 'abuseipdb', 'shodan', 'alienvault', 'urlhaus',
    'feodotracker', 'threatfox', 'malwarebazaar', 'c2_trackers',
    'tor_exit_nodes', 'ssl_blacklist', 'usom', 'greynoise', 'censys',
    'talos', 'pulsedive', 'threatcrowd', 'criminalip', 'ipqualityscore',
    'spamhaus', 'phishtank', 'circl', 'ip2proxy', 'triage', 'threatzone',
]

# These feeds were permanently removed from the supported investigation set.
# Keep them in one prompt guardrail so degraded legacy payloads never trigger
# recovery recommendations for feeds that cannot be restored.
PERMANENTLY_EXCLUDED_SOURCES = frozenset({"talos", "greynoise", "pulsedive", "circl"})


class LLMAnalyzer:
    """
    LLM-powered threat analysis using LOCAL (Ollama) or CLOUD (Anthropic) models.

    **LOCAL-FIRST APPROACH** (Recommended for Critical Infrastructure):
    - Uses Ollama for local, private analysis
    - No data leaves your infrastructure
    - Free, unlimited usage
    - Supports: Llama 3.1, Mistral, Qwen, DeepSeek, etc.

    **CLOUD OPTION** (Optional):
    - Uses Anthropic Claude API
    - Requires API key and costs money
    - Only use for non-sensitive data

    Provides:
    - Intelligent threat scoring
    - Context-aware analysis
    - Natural language summaries
    - Actionable recommendations
    """

    def __init__(self, config: Dict):
        """
        Initialize LLM analyzer.

        Args:
            config: Configuration dict
        """
        self.config = config

        # Determine LLM provider (local/cloud)
        llm_config = config.get('llm', {})
        self.provider = llm_config.get('provider', 'ollama')  # Default: local

        # Ollama settings
        self.ollama_endpoint = llm_config.get('ollama_endpoint', 'http://localhost:11434')
        self.ollama_model = llm_config.get('model', llm_config.get('ollama_model', 'llama3.2:3b'))

        # Anthropic settings (fallback)
        self.anthropic_key = config.get('api_keys', {}).get('anthropic', '')
        self.anthropic_model = 'claude-sonnet-4-20250514'

        # vLLM settings (OpenAI-compatible self-hosted)
        self.vllm_base_url = llm_config.get('vllm_base_url')
        self.vllm_api_key = llm_config.get('vllm_api_key')
        self.vllm_model = llm_config.get('vllm_model')

        self.timeout = aiohttp.ClientTimeout(total=120)  # Longer timeout for local LLM
        self.vllm_timeout = aiohttp.ClientTimeout(total=45, connect=10)

        _model_map = {'ollama': self.ollama_model, 'vllm': self.vllm_model, 'anthropic': self.anthropic_model}
        logger.info(f"[LLM] Provider: {self.provider} | Model: {_model_map.get(self.provider, self.anthropic_model)}")

    async def analyze_ioc_results(
        self,
        ioc: str,
        ioc_type: str,
        results: Dict,
        rag_context: Optional[list] = None,
        authoritative_verdict: Optional[str] = None,
        coverage: Optional[Dict] = None,
        dga: Optional[Dict] = None,
    ) -> Dict:
        """
        Analyze IOC investigation results using LLM.

        Args:
            ioc: The IOC investigated
            ioc_type: IOC type
            results: Investigation results from all sources
            rag_context: Optional list of retrieved knowledge base entries
            authoritative_verdict: Final coverage-aware verdict from the IOC
                investigator
            coverage: Coverage-aware source counts from the scoring engine

        Returns:
            LLM analysis with verdict and recommendations
        """
        try:
            # Prepare context for LLM
            context = self._prepare_ioc_context(ioc, ioc_type, results, dga=dga)

            # Build prompt
            score_breakdown = context.get('score_breakdown', {})
            sources_checked = len(score_breakdown)
            sources_flagged = sum(
                1 for item in score_breakdown.values()
                if isinstance(item, dict) and item.get('flagged') is True
            )

            # Findings and source counts explain the engine decision; they do
            # not independently derive a second verdict.
            engine_verdict = authoritative_verdict or "not supplied"
            findings_summary = (
                f"Scoring engine verdict: {engine_verdict}. "
                f"{sources_flagged} of {sources_checked} scoring sources flagged the IOC."
            )
            coverage_data = coverage if isinstance(coverage, dict) else results.get('coverage', {})
            if not isinstance(coverage_data, dict):
                coverage_data = {}

            dga_section = ''
            if 'dga' in context:
                dga_section = (
                    '**DGA Enrichment:**\n'
                    f"{json.dumps(context['dga'], indent=2)}\n"
                )

            source_status = context.get('source_status', {})

            prompt = f"""You are a senior SOC analyst specializing in critical infrastructure cybersecurity. 

Analyze this IOC investigation and provide a professional, actionable analysis:

IOC: {ioc}
Type: {ioc_type}
Threat Score: {results.get('threat_score', 0)}/100
Scoring Engine Verdict: {engine_verdict}
Source Coverage: {json.dumps(coverage_data, sort_keys=True)}

**Investigation Summary:**
{findings_summary}
Scoring Sources Checked: {sources_checked}
Scoring Sources Flagged: {sources_flagged}

**Key Findings:**
{json.dumps(context.get('key_findings', []), indent=2)}
**Scorer Source Breakdown (authoritative for source flags and score contributions):**
{json.dumps(score_breakdown, sort_keys=True)}
**Source Status:**
{json.dumps(source_status, indent=2)}
{dga_section}
{self._format_rag_section(rag_context)}
**IMPORTANT RULES:**
1. The scoring engine verdict above is authoritative. Explain that verdict; do not recalculate or replace it based on sources_flagged, score thresholds, or your own assessment.
1a. Use Scorer Source Breakdown as the sole authority for whether a scored source was flagged and which per-source score/weight contributed. Do not infer a scored source is clean or flagged from its raw status, listed, found, or score fields.
2. Do NOT hallucinate findings that don't exist
3. Base your analysis ONLY on the data provided above
4. If any source is degraded, state that the engine verdict reflects limited coverage and name the degraded sources.
5. Do NOT invent playbooks or standards; cite a knowledge-base entry only by its [N] marker.
6. If DGA confidence is below 70 or family is None, treat DGA as a weak signal.
7. Do not recommend allowlisting when any source is degraded.
8. ONLY reference source names that appear in the "Key Findings" or "Source Status" sections above. Do NOT mention any other source by name.
9. Recommend restoring a feed and re-running now only for degraded scored
    sources listed in scored_degraded. For degraded context sources, mention
    briefly that they are supporting evidence and do not affect the score.
    Never recommend restoring a permanently excluded source; permanently
    excluded sources are: {', '.join(sorted(PERMANENTLY_EXCLUDED_SOURCES))}.
    Do not suggest waiting days for a degraded scored source to recover.
10. If any source is degraded, do not recommend "maintaining" or "recording"
    a Clean status; describe the verdict as provisional.
11. Do not mention internal field names or JSON keys (including source_status,
    scored_degraded, context_degraded, responded, and not_applicable) in your
    user-facing analysis or recommendations. Describe these groups in plain
    language, such as degraded scoring sources or degraded context sources.
12. Copy each source name exactly as written in the Source Status section. Do
    not correct, alter, abbreviate, or concatenate source names.
13. VirusTotal detections formatted as M/N (for example, 11/92) mean M
    detections out of N VirusTotal scanning engines. Refer to N as engines,
    never as sources, and never call it "total sources".

Provide your analysis in a clear, professional format. Include:

1. **Threat Assessment** (2-3 sentences)
   - Summarize the investigation results accurately
   - Explain the scoring engine verdict shown above
   - Mention any specific findings from sources

2. **Recommendations** (3-5 actionable items)
   - If CLEAN: Monitoring/documentation actions
   - If SUSPICIOUS/MALICIOUS: Immediate actions for SOC team

Respond in JSON format:
{{
    "verdict": "{engine_verdict}",
    "analysis": "Explain the scoring engine verdict in 2-3 sentences.",
    "recommendations": ["rec1", "rec2", "rec3"]
}}

Keep it concise and factual."""

            # Call appropriate LLM provider
            if self.provider == 'ollama':
                response_data = await self._call_ollama_api(prompt)
            elif self.provider == 'vllm':
                response_data = await self._call_vllm_api(
                    prompt, raise_on_failure=True,
                )
            else:
                response_data = await self._call_anthropic_api(prompt)

            if response_data:
                # [GUARDRAIL ADDITION] Post-processing validation layer
                response_data = validate_llm_analysis(
                    response_data,
                    context,
                    threat_score=results.get('threat_score', 0),
                    all_known_sources=ALL_TI_SOURCES,
                    ioc_type=ioc_type,
                    rag_context=rag_context,
                    authoritative_verdict=authoritative_verdict,
                    coverage=coverage_data,
                )
                return response_data
            else:
                return {'error': 'Failed to get LLM response', 'provider': self.provider}

        except Exception as e:
            logger.error(f"[LLM] Analysis failed: {e}")
            if self.provider == 'vllm':
                return {
                    'error': 'Failed to get LLM response',
                    'provider': self.provider,
                    'exception_type': type(e).__name__,
                    'exception_message': str(e),
                }
            return {'error': str(e)}

    def _format_rag_section(self, rag_context: Optional[list]) -> str:
        """Format retrieved RAG knowledge base entries for prompt injection."""
        if not rag_context:
            return ""

        lines = ["\n**Relevant Knowledge Base Entries:**"]
        for i, doc in enumerate(rag_context, start=1):
            category = doc['metadata'].get('category', 'unknown')
            lines.append(f"[{i}] (source: {category}) {doc['text']}")
        lines.append("Reference the relevant entry above (by its [N]) ONLY if it is directly relevant to this specific IOC type and findings. Do NOT reference entries about domain registration, DGA, or other domain-specific concepts unless this IOC is actually a domain or URL.\n")
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    # [GUARDRAIL ADDITION] Post-processing hallucination check
    # ------------------------------------------------------------------ #
    def _validate_llm_analysis(self, llm_result: Dict, context: Dict) -> Dict:
        """
        Validate LLM output against verified findings to catch hallucinated
        source names that slipped past the prompt-level guardrail.

        This is a defense-in-depth layer: the prompt already instructs the
        LLM to only use provided data, but small local models (e.g. 3B
        parameter models) can still fabricate source names. This check
        flags such cases for analyst review instead of silently trusting
        the LLM output.

        Args:
            llm_result: Parsed JSON response from the LLM
            context: The context dict that was sent to the LLM
                     (contains 'key_findings' = list of verified sources)

        Returns:
            llm_result, with an added 'hallucination_warning' key if
            unverified source names are detected in the analysis text.
        """
        if not llm_result or 'analysis' not in llm_result:
            return llm_result

        # Source names that were actually confirmed (status == '✓')
        # and therefore legitimately sent to the LLM as key_findings
        valid_sources = {f['source'] for f in context.get('key_findings', [])}

        analysis_text = llm_result.get('analysis', '').lower()

        suspicious_mentions = [
            source_name for source_name in ALL_TI_SOURCES
            if source_name in analysis_text and source_name not in valid_sources
        ]

        if suspicious_mentions:
            logger.warning(
                f"[LLM Guardrail] Possible hallucination detected: LLM analysis "
                f"mentioned {suspicious_mentions} which were NOT in verified "
                f"findings {valid_sources or '(none)'}"
            )
            llm_result['hallucination_warning'] = (
                f"⚠️ Analyst Note: This AI-generated analysis references source(s) "
                f"{suspicious_mentions} that were not part of the verified findings. "
                f"Please cross-check manually before acting on this summary."
            )

        return llm_result

    async def analyze_email(
        self,
        email_data: Dict,
        rag_context: Optional[list] = None,
    ) -> Dict:
        """
        Analyze email using LLM.

        Args:
            email_data: Parsed email data
            rag_context: Optional list of retrieved knowledge base entries

        Returns:
            LLM analysis of email
        """
        try:
            # Prepare comprehensive context for LLM
            context = {
                'subject': email_data.get('subject', 'N/A'),
                'from': email_data.get('from', 'N/A'),
                'to': email_data.get('to', 'N/A'),
                'authentication': {
                    'spf': email_data.get('spf', 'N/A'),
                    'dkim': email_data.get('dkim', 'N/A'),
                    'dmarc': email_data.get('dmarc', 'N/A')
                },
                'header_anomalies': self._ensure_list(email_data.get('header_anomalies', [])),
                'link_mismatches': self._ensure_list(email_data.get('link_mismatches', [])),
                'lookalike_domains': self._ensure_list(email_data.get('lookalike_domains', [])),
                'html_obfuscation_score': email_data.get('html_obfuscation_score', 0),
                'qr_codes': self._ensure_list(email_data.get('qr_codes', [])),
                'brand_impersonation': self._ensure_list(email_data.get('brand_impersonation', [])),
                'ioc_summary': {
                    'total': email_data.get('ioc_count', 0),
                    'malicious': email_data.get('malicious_iocs', 0),
                    'malicious_urls': [u.get('ioc') for u in email_data.get('malicious_urls', [])[:3]],
                    'malicious_domains': [d.get('ioc') for d in email_data.get('malicious_domains', [])[:3]]
                },
                'attachment_summary': {
                    'total': email_data.get('attachment_count', 0),
                    'malicious': email_data.get('malicious_attachments', 0),
                    'malicious_files': [a.get('filename') for a in email_data.get('malicious_attachment_details', [])[:3]]
                },
                'base_score': email_data.get('base_score', 0),
                'composite_score': email_data.get('composite_score', 0),
                'forensics_score': email_data.get('forensics_score', 0),
                'capability_errors': self._ensure_list(email_data.get('capability_errors', [])),
            }

            lookalike_domains = []
            for item in context['lookalike_domains']:
                if isinstance(item, dict):
                    lookalike_domains.append(
                        f"{item.get('domain', 'N/A')} "
                        f"(brand={item.get('brand', 'N/A')}, "
                        f"similarity={item.get('similarity', 'N/A')}, "
                        f"risk={item.get('risk', 'N/A')})"
                    )
                else:
                    lookalike_domains.append(str(item))
            lookalike_summary = ', '.join(lookalike_domains) if lookalike_domains else 'None detected'

            capability_errors = []
            for item in context['capability_errors']:
                if isinstance(item, dict):
                    capability_errors.append(
                        f"{item.get('capability', 'unknown')} "
                        f"({item.get('status', 'unavailable')}): "
                        f"{item.get('message', 'capability incomplete')}"
                    )
                else:
                    capability_errors.append(str(item))
            capability_summary = '; '.join(capability_errors) if capability_errors else 'None reported'

            prompt = f"""You are a SOC analyst at specializing in email security and phishing detection.

Analyze this email investigation:

Subject: {context['subject']}
From: {context['from']}
To: {context['to']}

Authentication:
- SPF: {context['authentication']['spf']}
- DKIM: {context['authentication']['dkim']}
- DMARC: {context['authentication']['dmarc']}

Advanced Analysis Results:
- Header Anomalies: {len(context['header_anomalies'])}
- Link-Text Mismatches: {len(context['link_mismatches'])}
- Lookalike Domains: {lookalike_summary}
- HTML Obfuscation Score: {context['html_obfuscation_score']}/100
- QR Codes Detected: {len(context['qr_codes'])}
- Brand Impersonation: {len(context['brand_impersonation'])}

IOC Analysis:
- Total IOCs: {context['ioc_summary']['total']}
- Malicious: {context['ioc_summary']['malicious']}
{f"- Malicious URLs: {', '.join(context['ioc_summary']['malicious_urls'])}" if context['ioc_summary']['malicious_urls'] else ""}
{f"- Malicious Domains: {', '.join(context['ioc_summary']['malicious_domains'])}" if context['ioc_summary']['malicious_domains'] else ""}

Attachments:
- Total: {context['attachment_summary']['total']}
- Malicious: {context['attachment_summary']['malicious']}
{f"- Malicious Files: {', '.join(context['attachment_summary']['malicious_files'])}" if context['attachment_summary']['malicious_files'] else ""}

Scoring:
- Base Phishing Score: {context['base_score']}/100
- Forensics Score: {context['forensics_score']}/100
- Composite Score: {context['composite_score']}/100

Capability limitations:
- {capability_summary}
- Use rule and forensics scores as evidence; if the base score is high, explain before concluding CLEAN.

{self._format_rag_section(rag_context)}
Based on the above tool analysis, provide your professional assessment in JSON format:
{{
    "verdict": "PHISHING/SUSPICIOUS/CLEAN/UNKNOWN",
    "analysis": "Your concise analysis (2-3 sentences) explaining WHY this is phishing/clean/unknown based on the tool findings. Reference specific detections (e.g., 'lookalike domain paypa1.com', 'malicious attachment detected', 'links to known C2 infrastructure').",
    "recommendations": [
        "Block sender domain immediately",
        "Hunt for similar emails in mail gateway",
        "Add IOCs to threat intel platform"
    ]
}}

Be specific and reference the tool findings in your analysis."""

            if self.provider == 'ollama':
                response_data = await self._call_ollama_api(prompt)
            elif self.provider == 'vllm':
                response_data = await self._call_vllm_api(prompt)
            else:
                response_data = await self._call_anthropic_api(prompt)

            return response_data if response_data else {'error': 'Failed to analyze'}

        except Exception as e:
            logger.error(f"[LLM] Email analysis failed: {e}")
            return {'error': str(e)}

    async def analyze_file(self, file_data: Dict) -> Dict:
        """
        Analyze file using LLM.

        Args:
            file_data: File analysis data

        Returns:
            LLM analysis of file
        """
        try:
            # Prepare comprehensive context for LLM
            context = {
                'filename': file_data.get('filename', 'N/A'),
                'file_type': file_data.get('file_type', 'N/A'),
                'size_bytes': file_data.get('size_bytes', 0),
                'sha256': file_data.get('sha256', 'N/A')[:64],
                'hash_score': file_data.get('hash_score', 0),
                'architecture': file_data.get('architecture', 'N/A'),
                'signed': file_data.get('signature', {}).get('signed', False),
                'packer': file_data.get('packer_detection', {}).get('packer', 'None'),
                'packer_confidence': file_data.get('packer_detection', {}).get('confidence', 'N/A'),
                'entropy': file_data.get('entropy', 0),
                'entropy_category': file_data.get('entropy_category', 'unknown'),
                'suspicious_sections': [
                    f"{s.get('name', 'Unknown')} (entropy: {s.get('entropy', 0):.2f})" 
                    for s in file_data.get('suspicious_sections', [])[:3]
                ],
                'suspicious_imports': [
                    f"{imp.get('dll', 'Unknown')}: {', '.join(imp.get('suspicious_apis', [])[:3])}"
                    for imp in file_data.get('suspicious_imports', [])[:3]
                ],
                'anti_analysis': file_data.get('anti_analysis', []),
                'string_categories': self._process_string_categories(file_data.get('string_categories', {})),
                'registry_keys': file_data.get('registry_keys', [])[:3],
                'mutexes': file_data.get('mutexes', [])[:3],
                'yara_matches': [
                    {
                        'rule': m.get('rule', 'Unknown'),
                        'severity': m.get('meta', {}).get('severity', 'UNKNOWN')
                    }
                    for m in (file_data.get('yara_matches', []) if isinstance(file_data.get('yara_matches'), list) else [])
                ],
                'yara_match_count': file_data.get('yara_matches') if isinstance(file_data.get('yara_matches'), int) else len(file_data.get('yara_matches', [])),
                'malware_families': file_data.get('yara_malware_families', []),
                'ioc_count': file_data.get('ioc_count', 0),
                'malicious_iocs': file_data.get('malicious_iocs', 0),
                'malicious_ips': [ip.get('ioc') for ip in (file_data.get('malicious_ips') or [])[:3] if isinstance(ip, dict)],
                'malicious_domains': [d.get('ioc') for d in (file_data.get('malicious_domains') or [])[:3] if isinstance(d, dict)],
                'composite_score': file_data.get('composite_score', 0)
            }

            # Check if this is a text file with C2/IOC data
            is_text_file = file_data.get('file_type') == 'text'

            if is_text_file and file_data.get('c2_patterns'):
                prompt = self._build_text_file_prompt(file_data, context)
            else:
                prompt = self._build_standard_file_prompt(file_data, context)

            if self.provider == 'ollama':
                response_data = await self._call_ollama_api(prompt)
            elif self.provider == 'vllm':
                response_data = await self._call_vllm_api(prompt)
            else:
                response_data = await self._call_anthropic_api(prompt)

            return response_data if response_data else {'error': 'Failed to analyze'}

        except Exception as e:
            logger.error(f"[LLM] File analysis failed: {e}")
            return {'error': str(e)}

    def _build_text_file_prompt(self, file_data: Dict, context: Dict) -> str:
        """Build LLM prompt for text files with C2/IOC indicators."""
        c2_patterns = file_data.get('c2_patterns', [])
        ip_addresses = file_data.get('ip_addresses', [])
        urls = file_data.get('urls', [])
        encoded = file_data.get('encoded_content', [])
        creds = file_data.get('credential_indicators', [])
        ioc_results = file_data.get('ioc_results', [])

        c2_section = ""
        if c2_patterns:
            c2_lines = []
            for p in c2_patterns[:10]:
                c2_lines.append(f"  - [{p.get('severity', 'unknown').upper()}] {p.get('description', '')} "
                               f"(MITRE: {p.get('mitre', 'N/A')}, matches: {p.get('match_count', 0)})")
            c2_section = "C2 Communication Patterns Found:\n" + chr(10).join(c2_lines)

        ip_section = ""
        suspicious_ips = [ip for ip in ip_addresses if ip.get('suspicious') and not ip.get('is_private')]
        external_ips = [ip for ip in ip_addresses if not ip.get('is_private')]
        if suspicious_ips:
            ip_lines = [f"  - {ip['ip']}" + (f":{ip['port']}" if ip.get('port') else '') +
                       f" ({', '.join(ip.get('reasons', []))})" for ip in suspicious_ips[:10]]
            ip_section = f"Suspicious External IPs ({len(suspicious_ips)}):\n" + chr(10).join(ip_lines)
        elif external_ips:
            ip_lines = [f"  - {ip['ip']}" + (f":{ip['port']}" if ip.get('port') else '') for ip in external_ips[:10]]
            ip_section = f"External IPs Found ({len(external_ips)}):\n" + chr(10).join(ip_lines)

        url_section = ""
        suspicious_urls = [u for u in urls if u.get('suspicious')]
        if suspicious_urls:
            url_lines = [f"  - {u['url'][:100]} ({', '.join(u.get('reasons', []))})" for u in suspicious_urls[:10]]
            url_section = f"Suspicious URLs ({len(suspicious_urls)}):\n" + chr(10).join(url_lines)

        ioc_section = ""
        if ioc_results:
            malicious = [r for r in ioc_results if r.get('verdict') == 'MALICIOUS']
            suspicious = [r for r in ioc_results if r.get('verdict') == 'SUSPICIOUS']
            ioc_section = f"IOC Investigation Results:\n  - Total investigated: {len(ioc_results)}\n"
            if malicious:
                ioc_section += f"  - MALICIOUS: {len(malicious)} IOCs\n"
                for r in malicious[:5]:
                    ioc_section += f"    - {r.get('ioc', 'N/A')} (score: {r.get('threat_score', 0)})\n"
            if suspicious:
                ioc_section += f"  - SUSPICIOUS: {len(suspicious)} IOCs\n"

        return f"""You are a SOC analyst performing threat intelligence analysis on a text file.
This file contains potential indicators of compromise (IOCs), C2 configuration data, or threat intelligence information.

File Information:
- Filename: {context['filename']}
- Type: Text File
- Size: {context['size_bytes']:,} bytes

{c2_section}

{ip_section}

{url_section}

{f"Encoded Content: {len(encoded)} encoded blocks detected" if encoded else ""}
{f"Credential Indicators: {len(creds)} potential credential leaks" if creds else ""}

{ioc_section}

Composite Score: {context['composite_score']}/100

Based on the above analysis, provide your professional threat assessment in JSON format:
{{
    "verdict": "MALICIOUS/SUSPICIOUS/CLEAN",
    "analysis": "Your concise analysis (2-3 sentences). Is this a C2 configuration file? A threat intelligence report? A malware sample output? A data exfiltration log? Explain what the IOCs indicate - are they known malicious infrastructure? What threat actor or campaign might be involved?",
    "recommendations": [
        "Block identified C2 IPs at firewall",
        "Hunt for connections to identified infrastructure in SIEM",
        "Check for lateral movement from affected systems",
        "Update threat intelligence feeds with extracted IOCs"
    ]
}}

Be specific and reference the actual IOC findings in your analysis."""

    def _build_standard_file_prompt(self, file_data: Dict, context: Dict) -> str:
        """Build standard LLM prompt for binary/script files."""
        return f"""You are a malware analyst at  Technologies. Analyze this file investigation:

File Information:
- Filename: {context['filename']}
- Type: {context['file_type']}
- Size: {context['size_bytes']:,} bytes
- SHA256: {context['sha256']}

Threat Intelligence:
- Hash Score: {context['hash_score']}/100

PE Analysis (if applicable):
- Architecture: {context['architecture']}
- Signed: {context['signed']}
- Packer: {context['packer']} ({context['packer_confidence']} confidence)
- Entropy: {context['entropy']:.2f} ({context['entropy_category']})
{f"- Suspicious Sections: {', '.join(context['suspicious_sections'])}" if context['suspicious_sections'] else ""}
{f"- Suspicious Imports: {chr(10).join(['  - ' + imp for imp in context['suspicious_imports']])}" if context['suspicious_imports'] else ""}
{f"- Anti-Analysis Techniques: {', '.join(context['anti_analysis'][:3])}" if context['anti_analysis'] else ""}

String Analysis:
{chr(10).join([f"- {cat}: {count} strings" for cat, count in context['string_categories'].items()]) if context['string_categories'] else "- No suspicious strings"}
{f"- Registry Keys: {', '.join(context['registry_keys'])}" if context['registry_keys'] else ""}
{f"- Mutexes: {', '.join(context['mutexes'])}" if context['mutexes'] else ""}

YARA Analysis:
- Matches: {len(context['yara_matches'])} rules
{chr(10).join([f"  - {m['rule']} ({m['severity']})" for m in context['yara_matches']]) if context['yara_matches'] else ""}
{f"- Identified Families: {', '.join(context['malware_families'])}" if context['malware_families'] else ""}

Embedded IOC Analysis:
- Total IOCs: {context['ioc_count']}
- Malicious: {context['malicious_iocs']}
{f"- Malicious IPs: {', '.join(context['malicious_ips'])}" if context['malicious_ips'] else ""}
{f"- Malicious Domains: {', '.join(context['malicious_domains'])}" if context['malicious_domains'] else ""}

Composite Score: {context['composite_score']}/100

Based on the above tool analysis, provide your professional assessment in JSON format:
{{
    "verdict": "MALICIOUS/SUSPICIOUS/CLEAN",
    "analysis": "Your concise analysis (2-3 sentences) explaining the malware behavior, family, and threat. Reference specific tool findings (e.g., 'QakBot detected via YARA', 'UPX packer with entropy 7.8', 'C2 communication to known infrastructure').",
    "recommendations": [
        "Isolate infected systems immediately",
        "Block C2 IPs/domains at firewall",
        "Hunt for mutex across network",
        "Check for registry key modifications"
    ]
}}

Be specific and reference the tool findings in your analysis."""

    async def _call_ollama_api(self, prompt: str) -> Optional[Dict]:
        """
        Call Ollama local LLM API.

        Args:
            prompt: Analysis prompt

        Returns:
            Parsed JSON response or None
        """
        try:
            logger.info(f"[LLM] Calling Ollama ({self.ollama_model})...")

            payload = {
                'model': self.ollama_model,
                'prompt': prompt,
                'stream': False,
                'format': 'json',  # Request JSON output
                'options': {
                    'temperature': 0.2,
                    'repeat_penalty': 1.3,
                    'num_predict': 512,
                },
            }

            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    f'{self.ollama_endpoint}/api/generate',
                    json=payload
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        response_text = data.get('response', '')

                        # Parse JSON from response
                        try:
                            return json.loads(response_text)
                        except json.JSONDecodeError:
                            # Try to extract JSON from markdown code blocks
                            import re
                            json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response_text, re.DOTALL)
                            if json_match:
                                return json.loads(json_match.group(1))

                            # Try to find JSON object in text
                            start = response_text.find('{')
                            end = response_text.rfind('}') + 1
                            if start >= 0 and end > start:
                                return json.loads(response_text[start:end])

                            logger.warning(f"[LLM] Could not parse JSON from Ollama response")
                            return {'raw_response': response_text}
                    else:
                        body = await response.text()
                        logger.error(f"[LLM] Ollama API error {response.status}: {body[:200]}")
                        return None

        except aiohttp.ClientConnectorError:
            logger.error(
                f"[LLM] Cannot connect to Ollama at {self.ollama_endpoint}. "
                "Is Ollama running? Start it with: ollama serve"
            )
            return None
        except Exception as e:
            logger.error(f"[LLM] Ollama API call failed: {e}")
            return None

    async def _call_vllm_api(
        self, prompt: str, raise_on_failure: bool = False,
    ) -> Optional[Dict]:
        """
        Call vLLM OpenAI-compatible API.

        Args:
            prompt: Analysis prompt

        Returns:
            Parsed JSON response or None
        """
        if not self.vllm_base_url:
            logger.warning("[LLM] No vLLM base URL configured")
            return None

        for attempt in range(2):
            try:
                logger.info(f"[LLM] Calling vLLM ({self.vllm_model})...")

                headers = {
                    'content-type': 'application/json',
                }
                if self.vllm_api_key:
                    headers['Authorization'] = f'Bearer {self.vllm_api_key}'

                payload = {
                    'model': self.vllm_model,
                    'messages': [
                        {'role': 'user', 'content': prompt}
                    ]
                }

                async with aiohttp.ClientSession(timeout=self.vllm_timeout) as session:
                    async with session.post(
                        f'{self.vllm_base_url}/v1/chat/completions',
                        headers=headers,
                        json=payload
                    ) as response:
                        if response.status == 200:
                            data = await response.json()
                            text = data['choices'][0]['message']['content']

                            # Parse JSON from response
                            try:
                                return json.loads(text)
                            except json.JSONDecodeError:
                                # Try to extract JSON from markdown code blocks
                                json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
                                if json_match:
                                    return json.loads(json_match.group(1))

                                # Try to find JSON object in text
                                start = text.find('{')
                                end = text.rfind('}') + 1
                                if start >= 0 and end > start:
                                    return json.loads(text[start:end])

                                logger.warning(f"[LLM] Could not parse JSON from vLLM response")
                                return {'raw_response': text}
                        else:
                            body = await response.text()
                            logger.error(f"[LLM] vLLM API error {response.status}: {body[:200]}")
                            return None

            except aiohttp.ClientConnectorError as e:
                logger.error(
                    f"[LLM] vLLM API call failed: {type(e).__name__}: {e!r}; "
                    f"Cannot connect to vLLM at {self.vllm_base_url}. "
                    "Is the vLLM server running?"
                )
                if attempt == 0:
                    continue
                if raise_on_failure:
                    raise
                return None
            except asyncio.TimeoutError as e:
                logger.error(f"[LLM] vLLM API call failed: {type(e).__name__}: {e!r}")
                if attempt == 0:
                    continue
                if raise_on_failure:
                    raise
                return None
            except Exception as e:
                logger.error(f"[LLM] vLLM API call failed: {type(e).__name__}: {e!r}")
                if raise_on_failure:
                    raise
                return None

        return None

    async def _call_anthropic_api(self, prompt: str) -> Optional[Dict]:
        """
        Call Anthropic Claude API.

        Args:
            prompt: Analysis prompt

        Returns:
            Parsed JSON response or None
        """
        if not self.anthropic_key:
            logger.warning("[LLM] No Anthropic API key configured")
            return {'error': 'No Anthropic API key configured'}

        try:
            logger.info(f"[LLM] Calling Anthropic ({self.anthropic_model})...")

            headers = {
                'anthropic-version': '2023-06-01',
                'content-type': 'application/json',
                'x-api-key': self.anthropic_key
            }

            payload = {
                'model': self.anthropic_model,
                'max_tokens': 2000,
                'messages': [
                    {'role': 'user', 'content': prompt}
                ]
            }

            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    'https://api.anthropic.com/v1/messages',
                    headers=headers,
                    json=payload
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        content = data.get('content', [])

                        if content and content[0].get('type') == 'text':
                            text = content[0].get('text', '')

                            # Extract JSON from response
                            try:
                                # Try to find JSON in response
                                start = text.find('{')
                                end = text.rfind('}') + 1
                                if start >= 0 and end > start:
                                    json_str = text[start:end]
                                    return json.loads(json_str)
                            except:
                                pass

                            return {'raw_response': text}
                    else:
                        logger.error(f"[LLM] Anthropic API error: {response.status}")
                        return None

        except Exception as e:
            logger.error(f"[LLM] Anthropic API call failed: {e}")
            return None

    def _ensure_list(self, value) -> list:
        """
        Ensure value is a list.

        Args:
            value: Can be list, int, or anything

        Returns:
            List representation
        """
        if isinstance(value, list):
            return value
        elif isinstance(value, int):
            return [value]
        elif value is None:
            return []
        else:
            return [value]

    def _process_string_categories(self, string_categories) -> Dict:
        """
        Process string_categories - handle both dict and list formats.

        Args:
            string_categories: Can be dict or list

        Returns:
            Dict with category counts
        """
        if isinstance(string_categories, dict):
            # Already dict, process normally
            return {
                cat: len(strings) if isinstance(strings, list) else strings
                for cat, strings in string_categories.items()
            }
        elif isinstance(string_categories, list):
            # List format, count categories
            from collections import Counter
            category_counts = Counter()
            for item in string_categories:
                if isinstance(item, dict) and 'category' in item:
                    category_counts[item['category']] += 1
            return dict(category_counts)
        else:
            return {}

    def _prepare_ioc_context(
        self,
        ioc: str,
        ioc_type: str,
        results: Dict,
        dga: Optional[Dict] = None,
    ) -> Dict:
        """Prepare investigation results for LLM context."""
        # Extract key findings
        context = {
            'ioc': ioc,
            'type': ioc_type,
            'threat_score': results.get('threat_score', 0),
            'sources_flagged': 0,
            'score_breakdown': {},
            'key_findings': [],
            'source_status': {
                'responded': [],
                'scored_degraded': [],
                'context_degraded': [],
                'not_applicable': [],
            },
        }

        # Extract important findings from each source
        sources = results.get('sources', {})
        score_breakdown = results.get('score_breakdown')
        if not isinstance(score_breakdown, dict):
            from src.scoring.score_breakdown import build_ioc_score_breakdown

            score_breakdown = build_ioc_score_breakdown(results)
        context['score_breakdown'] = score_breakdown
        scored_source_names = {str(name).lower() for name in score_breakdown}
        context['sources_flagged'] = sum(
            1 for item in score_breakdown.values()
            if isinstance(item, dict) and item.get('flagged') is True
        )
        for source_name, item in score_breakdown.items():
            if isinstance(item, dict) and item.get('flagged') is True:
                context['key_findings'].append({
                    'source': source_name,
                    'flagged': True,
                    'score_used': item.get('score_used'),
                    'weight': item.get('weight'),
                    'scored': item.get('scored') is True,
                })
        for source_name, source_data in sources.items():
            source_data = source_data or {}
            status = source_data.get('status')

            if source_data.get('not_applicable') is True:
                context['source_status']['not_applicable'].append(source_name)
            elif (
                status == '⚠'
                or 'error' in source_data
                or source_data.get('feed_status') == 'unavailable'
            ):
                reason = source_data.get('error') or source_data.get('reason')
                if not reason and source_data.get('feed_status') == 'unavailable':
                    reason = 'feed_status=unavailable'
                if not reason:
                    reason = 'source returned a degraded status'
                degraded_source = {
                    'source': source_name,
                    'reason': str(reason),
                }
                if source_name.lower() in scored_source_names:
                    context['source_status']['scored_degraded'].append(degraded_source)
                else:
                    context['source_status']['context_degraded'].append(degraded_source)
            else:
                context['source_status']['responded'].append(source_name)

            if source_name in context['score_breakdown']:
                continue

            if source_data.get('status') == '✓':
                finding = {'source': source_name}

                # Add relevant data
                if 'botnet' in source_data:
                    finding['botnet'] = source_data['botnet']
                if 'malware' in source_data:
                    finding['malware'] = source_data['malware']
                if 'threat' in source_data:
                    finding['threat'] = source_data['threat']
                if 'detections' in source_data:
                    finding['detections'] = source_data['detections']

                context['key_findings'].append(finding)

        if dga is not None:
            context['dga'] = {
                'is_dga': dga.get('is_dga'),
                'confidence': dga.get('confidence'),
                'family': dga.get('family', dga.get('dga_family_guess')),
            }

        return context

    async def generate_detection_rules(self, analysis_result: Dict, rule_type: str = 'all') -> Dict:
        """
        Generate detection rules using LLM based on analysis results.

        Args:
            analysis_result: File or IOC analysis results
            rule_type: 'kql', 'sigma', 'yara', 'spl', or 'all'

        Returns:
            Dict with generated rules for each platform
        """
        try:
            # Extract relevant info
            ioc = analysis_result.get('ioc', '')
            ioc_type = analysis_result.get('ioc_type', '')
            filename = analysis_result.get('filename', '')
            sha256 = analysis_result.get('sha256', '')

            # Build context
            malware_families = analysis_result.get('malware_families', [])
            threat_score = analysis_result.get('threat_score', 0)
            suspicious_strings = analysis_result.get('suspicious_strings', [])
            registry_keys = analysis_result.get('registry_keys', [])

            # Construct prompt
            prompt = f"""You are a detection engineer at  Technologies. Generate detection rules based on this analysis.

Analysis Context:
- IOC: {ioc or filename or sha256}
- Type: {ioc_type or 'file'}
- Threat Score: {threat_score}/100
- Malware Families: {', '.join(malware_families) if malware_families else 'Unknown'}
- Suspicious Strings: {', '.join(suspicious_strings[:5]) if suspicious_strings else 'None'}
- Registry Keys: {', '.join(registry_keys[:3]) if registry_keys else 'None'}

Generate detection rules in JSON format:
{{
    "kql": "Full KQL query for Microsoft Defender/Sentinel",
    "sigma": "YAML SIGMA rule",
    "yara": "YARA rule with strings and conditions",
    "spl": "Splunk SPL query"
}}

Make rules specific to the threat indicators found. Include:
- Proper escaping
- Meaningful rule names
- Detection logic based on actual findings
- Comments explaining the detection"""

            # Call LLM
            if self.provider == 'ollama':
                response_data = await self._call_ollama_api(prompt)
            elif self.provider == 'vllm':
                response_data = await self._call_vllm_api(prompt)
            else:
                response_data = await self._call_anthropic_api(prompt)

            if response_data:
                return response_data
            else:
                # Fallback to basic rules
                return self._generate_basic_rules(analysis_result)

        except Exception as e:
            logger.error(f"[LLM] Rule generation failed: {e}")
            return self._generate_basic_rules(analysis_result)

    async def translate_firewall_to_fortigate(
        self, abstract_rule: str, ioc: str, ioc_type: str,
        verdict: str, malware_family: str
    ) -> Optional[str]:
        """
        Translate a vendor-neutral firewall blocklist entry into real
        FortiGate CLI syntax using the configured LLM provider.

        Returns the FortiGate CLI string on success, or None if the LLM
        call failed or the output didn't pass a basic sanity check
        (caller should treat None as "translation unavailable" and NOT
        surface a firewall_fortigate key at all — never fabricate output).
        """
        if (
            str(verdict).strip().upper() == 'CLEAN'
            or str(abstract_rule).startswith('#')
        ):
            return None

        try:
            prompt = f"""You are a network security engineer configuring a FortiGate firewall.

Translate this abstract blocklist entry into valid FortiGate CLI syntax
that blocks the indicator via an address object + firewall policy deny rule.

Abstract entry: {abstract_rule}
Indicator: {ioc}
Indicator type: {ioc_type}
Verdict: {verdict}
Malware family: {malware_family}

Requirements:
1. Use proper FortiGate CLI syntax (config firewall address / edit / set subnet or set fqdn / next / end)
2. Include a firewall policy block that denies traffic to/from this address object
3. Add a comment referencing the malware family and verdict
4. Be syntactically correct and deployable as-is

Respond in JSON format:
{{
    "fortigate_cli": "the full CLI configuration block as a single string with \\n for newlines"
}}

Return ONLY the JSON object, no other text."""

            if self.provider == 'ollama':
                response_data = await self._call_ollama_api(prompt)
            elif self.provider == 'vllm':
                response_data = await self._call_vllm_api(prompt)
            else:
                response_data = await self._call_anthropic_api(prompt)

            if not response_data or not isinstance(response_data, dict):
                return None

            cli = response_data.get('fortigate_cli', '')
            if not isinstance(cli, str) or not cli.strip():
                return None

            # Basic sanity check — must look like real FortiGate config blocks.
            # This is NOT full syntax validation (no FortiGate device to test
            # against), just a guard against obviously-wrong LLM output.
            cli_lower = cli.lower()
            required_markers = ('config firewall', 'edit', 'end')
            if not all(marker in cli_lower for marker in required_markers):
                logger.warning(
                    f"[LLM] FortiGate translation for {ioc} failed sanity check, discarding"
                )
                return None

            return cli

        except Exception as e:
            logger.error(f"[LLM] FortiGate translation failed for {ioc}: {e}")
            return None

    def _generate_basic_rules(self, analysis_result: Dict) -> Dict:
        """Generate basic rules as fallback."""
        ioc = analysis_result.get('ioc', '')
        ioc_type = analysis_result.get('ioc_type', 'unknown')

        rules = {
            'kql': f'DeviceNetworkEvents | where RemoteIP == "{ioc}" or RemoteUrl has "{ioc}"',
            'sigma': f"""title: IOC Detection - {ioc}
detection:
  selection:
    DestinationIp|contains: '{ioc}'
  condition: selection""",
            'yara': f'''rule IOC_Detection {{
    strings:
        $ioc = "{ioc}"
    condition:
        $ioc
}}''',
            'spl': f'index=* ("{ioc}")'
        }

        return rules
