"""
Author: SOCPOW
Text File Analyzer - Extracts malicious indicators (IOCs) from text files
(txt, log, csv, conf, cfg, ini, json, xml, yaml) and detects C2 communication patterns.
"""

import re
import math
import base64
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from collections import Counter

from ..utils.helpers import is_domain_or_subdomain

logger = logging.getLogger(__name__)


class TextFileAnalyzer:
    """Analyze malicious indicators in text files."""

    C2_PATTERNS = {
        'ip_port': {
            'pattern': r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?):(\d{1,5})\b',
            'severity': 'high',
            'description': 'IP:Port combination - potential C2 endpoint',
            'mitre': 'T1071'
        },
        'http_ip': {
            'pattern': r'https?://(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?::\d+)?(?:/[^\s]*)?',
            'severity': 'high',
            'description': 'HTTP connection to raw IP - likely C2 callback',
            'mitre': 'T1071.001'
        },
        'beacon_sleep': {
            'pattern': r'(?:sleep|interval|beacon|jitter|callback|checkin|heartbeat)\s*[=:]\s*\d+',
            'severity': 'critical',
            'description': 'Beacon configuration parameter',
            'mitre': 'T1573'
        },
        'c2_framework': {
            'pattern': r'(?:cobalt\s*strike|metasploit|meterpreter|empire|covenant|sliver|havoc|brute\s*ratel|mythic|merlin|poshc2|silenttrinity)',
            'severity': 'critical',
            'description': 'Known C2 framework reference',
            'mitre': 'T1219'
        },
        'dns_tunnel': {
            'pattern': r'(?:dns|nslookup|dig)\s+(?:txt|cname|mx|aaaa|a)\s+[a-zA-Z0-9]{30,}\.',
            'severity': 'high',
            'description': 'Possible DNS tunneling - long subdomain query',
            'mitre': 'T1071.004'
        },
        'ps_download': {
            'pattern': r'(?:Invoke-WebRequest|wget|curl|DownloadString|DownloadFile|Start-BitsTransfer|Net\.WebClient|Invoke-RestMethod)',
            'severity': 'high',
            'description': 'Download cradle command',
            'mitre': 'T1105'
        },
        'reverse_shell': {
            'pattern': r'(?:nc|ncat|netcat|socat)\s+.*-[el]|bash\s+-i\s+>&|python[23]?\s+-c\s+.*socket|/dev/tcp/|mkfifo\s+/tmp/',
            'severity': 'critical',
            'description': 'Reverse shell command',
            'mitre': 'T1059'
        },
        'persistence': {
            'pattern': r'(?:HKLM|HKCU)\\\\(?:Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run|SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image)',
            'severity': 'high',
            'description': 'Registry persistence path',
            'mitre': 'T1547.001'
        },
        'schtask': {
            'pattern': r'schtasks\s+/(?:create|change)|at\s+\d{1,2}:\d{2}\s+/|crontab\s+-[el]',
            'severity': 'high',
            'description': 'Scheduled task creation',
            'mitre': 'T1053'
        },
        'cred_harvest': {
            'pattern': r'(?:mimikatz|sekurlsa|lsass|hashdump|lazagne|cred\s*dump|SAM\s+hive|SYSTEM\s+hive|ntds\.dit)',
            'severity': 'critical',
            'description': 'Credential harvesting tool/technique',
            'mitre': 'T1003'
        },
        'lateral_movement': {
            'pattern': r'(?:psexec|wmiexec|smbexec|atexec|dcomexec|evil-?winrm|crackmapexec|impacket)',
            'severity': 'critical',
            'description': 'Lateral movement tool',
            'mitre': 'T1021'
        },
        'exfiltration': {
            'pattern': r'(?:exfil|upload|POST\s+.*\.php|rclone|mega-?cmd|curl\s+.*-d\s+@|base64\s+.*\|\s*curl)',
            'severity': 'high',
            'description': 'Data exfiltration indicator',
            'mitre': 'T1041'
        },
    }

    ENCODING_PATTERNS = {
        'base64_block': {
            'pattern': r'(?:[A-Za-z0-9+/]{40,}={0,2})',
            'severity': 'medium',
            'description': 'Base64 encoded content block',
        },
        'hex_encoded': {
            'pattern': r'(?:0x[0-9a-fA-F]{2}\s*[,;]\s*){8,}|(?:\\x[0-9a-fA-F]{2}){8,}',
            'severity': 'medium',
            'description': 'Hex-encoded content (possible shellcode)',
        },
        'powershell_encoded': {
            'pattern': r'-(?:enc|EncodedCommand)\s+[A-Za-z0-9+/=]{20,}',
            'severity': 'critical',
            'description': 'PowerShell encoded command',
            'mitre': 'T1027'
        },
        'xor_key': {
            'pattern': r'(?:xor|XOR)\s*(?:key|KEY)?\s*[=:]\s*(?:0x)?[0-9a-fA-F]+',
            'severity': 'high',
            'description': 'XOR encryption key',
            'mitre': 'T1140'
        },
    }

    CREDENTIAL_PATTERNS = {
        'password_field': {
            'pattern': r'(?:password|passwd|pwd|pass|secret|token|api_?key|auth_?token|access_?key|private_?key)\s*[=:]\s*\S+',
            'severity': 'high',
            'description': 'Credential or secret in plaintext',
        },
        'aws_key': {
            'pattern': r'(?:AKIA|ASIA)[A-Z0-9]{16}',
            'severity': 'critical',
            'description': 'AWS Access Key ID',
        },
        'private_key': {
            'pattern': r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
            'severity': 'critical',
            'description': 'Private key detected',
        },
        'connection_string': {
            'pattern': r'(?:mongodb|mysql|postgres|redis|amqp|smtp|ftp)://\S+:\S+@',
            'severity': 'critical',
            'description': 'Database/service connection string with credentials',
        },
        'jwt_token': {
            'pattern': r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+',
            'severity': 'medium',
            'description': 'JWT token',
        },
    }

    NETWORK_PATTERNS = {
        'suspicious_ports': {
            'ports': [4444, 5555, 1234, 8443, 8080, 9090, 31337, 1337, 6666, 6667,
                      4443, 443, 80, 8888, 7777, 3389, 5900, 5985, 5986, 2222,
                      53, 25, 587, 465, 110, 143, 993, 995],
            'description': 'Known suspicious port',
        },
        'user_agent': {
            'pattern': r'User-Agent:\s*(.+)',
            'severity': 'info',
            'description': 'HTTP User-Agent string',
        },
        'http_method': {
            'pattern': r'(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT)\s+(?:https?://|/)\S+',
            'severity': 'medium',
            'description': 'HTTP request',
        },
    }

    PRIVATE_RANGES = [
        (r'^10\.', 'RFC1918'),
        (r'^172\.(1[6-9]|2[0-9]|3[0-1])\.', 'RFC1918'),
        (r'^192\.168\.', 'RFC1918'),
        (r'^127\.', 'Loopback'),
        (r'^169\.254\.', 'Link-local'),
        (r'^0\.', 'Reserved'),
    ]

    def __init__(self):
        self._compile_patterns()

    def _compile_patterns(self):
        self._compiled_c2 = {}
        for name, info in self.C2_PATTERNS.items():
            try:
                self._compiled_c2[name] = re.compile(info['pattern'], re.IGNORECASE | re.MULTILINE)
            except re.error as e:
                logger.warning(f"[TEXT] Failed to compile C2 pattern '{name}': {e}")

        self._compiled_encoding = {}
        for name, info in self.ENCODING_PATTERNS.items():
            try:
                self._compiled_encoding[name] = re.compile(info['pattern'], re.IGNORECASE | re.MULTILINE)
            except re.error as e:
                logger.warning(f"[TEXT] Failed to compile encoding pattern '{name}': {e}")

        self._compiled_creds = {}
        for name, info in self.CREDENTIAL_PATTERNS.items():
            try:
                self._compiled_creds[name] = re.compile(info['pattern'], re.IGNORECASE | re.MULTILINE)
            except re.error as e:
                logger.warning(f"[TEXT] Failed to compile credential pattern '{name}': {e}")

    def _is_private_ip(self, ip: str) -> bool:
        for pattern, _ in self.PRIVATE_RANGES:
            if re.match(pattern, ip):
                return True
        return False

    def _extract_ips(self, content: str) -> List[Dict]:
        ip_pattern = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
        found = ip_pattern.findall(content)

        results = []
        seen = set()
        for ip in found:
            if ip in seen:
                continue
            seen.add(ip)

            is_private = self._is_private_ip(ip)

            port_match = re.search(re.escape(ip) + r':(\d{1,5})', content)
            port = int(port_match.group(1)) if port_match else None

            context_pattern = re.compile(r'.{0,50}' + re.escape(ip) + r'.{0,50}', re.DOTALL)
            context_matches = context_pattern.findall(content)
            context = context_matches[0].strip() if context_matches else ''

            suspicious = False
            reasons = []

            if not is_private:
                if re.search(r'https?://' + re.escape(ip), content):
                    suspicious = True
                    reasons.append('HTTP connection to raw IP')

                if port and port in self.NETWORK_PATTERNS['suspicious_ports']['ports']:
                    suspicious = True
                    reasons.append(f'Suspicious port {port}')

                # Check if in C2 context. Word-boundary regex is used instead of
                # plain substring matching so short/ambiguous keywords (e.g. "c2",
                # "control") only match standalone tokens, not substrings buried
                # inside unrelated words (e.g. "control" inside "controller",
                # "c2" inside "src2_backup").
                c2_context_keywords = ['c2', 'c&c', 'command', 'control', 'beacon', 'callback',
                                       'implant', 'payload', 'shell', 'reverse', 'connect', 'listener']
                context_lower = context.lower()
                for kw in c2_context_keywords:
                    if re.search(r'\b' + re.escape(kw) + r'\b', context_lower):
                        suspicious = True
                        reasons.append(f'C2 context keyword: {kw}')
                        break

            results.append({
                'ip': ip,
                'port': port,
                'is_private': is_private,
                'suspicious': suspicious,
                'reasons': reasons,
                'context': context[:100],
                'occurrences': content.count(ip)
            })

        return results

    def _extract_urls(self, content: str) -> List[Dict]:
        url_pattern = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
        found = url_pattern.findall(content)

        whitelist_domains = {
            'microsoft.com', 'google.com', 'github.com', 'w3.org',
            'schema.org', 'apple.com', 'mozilla.org', 'wikipedia.org',
        }

        results = []
        seen = set()
        for url in found:
            url_clean = url.rstrip('.,;:)')
            if url_clean in seen:
                continue
            seen.add(url_clean)

            suspicious = False
            reasons = []

            try:
                from urllib.parse import urlparse
                parsed = urlparse(url_clean)
                host = parsed.hostname or ''
                port = parsed.port
                path = parsed.path

                ip_check = re.match(r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$', host)
                if ip_check and not self._is_private_ip(host):
                    suspicious = True
                    reasons.append('URL with raw IP address')

                suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.club',
                                   '.work', '.bid', '.download', '.win', '.stream', '.racing']
                for tld in suspicious_tlds:
                    if host.endswith(tld):
                        suspicious = True
                        reasons.append(f'Suspicious TLD: {tld}')
                        break

                suspicious_paths = ['/admin', '/shell', '/cmd', '/exec', '/upload', '/gate',
                                    '/panel', '/login.php', '/post.php', '/beacon', '/c2',
                                    '.exe', '.ps1', '.bat', '.vbs', '.hta', '.dll']
                for sp in suspicious_paths:
                    if sp in path.lower():
                        suspicious = True
                        reasons.append(f'Suspicious path: {sp}')
                        break

                is_whitelisted = any(
                    is_domain_or_subdomain(host, domain)
                    for domain in whitelist_domains
                )

            except Exception:
                is_whitelisted = False
                host = url_clean

            results.append({
                'url': url_clean,
                'host': host,
                'suspicious': suspicious,
                'is_whitelisted': is_whitelisted if 'is_whitelisted' in dir() else False,
                'reasons': reasons,
                'occurrences': content.count(url_clean[:50])
            })

        return results

    def _extract_domains(self, content: str) -> List[Dict]:
        domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|info|biz|xyz|top|club|tk|ml|ga|cf|gq|ru|cn|br|de|uk|fr|it|au|ca|nl|se|no|fi|dk|pl|cz|sk|hu|ro|bg|ua|kz|us|gov|mil|edu)\b', re.IGNORECASE)
        found = domain_pattern.findall(content)

        seen = set()
        results = []
        whitelist = {'microsoft.com', 'google.com', 'github.com', 'w3.org', 'example.com',
                     'localhost.com', 'schema.org', 'apple.com', 'mozilla.org'}

        for domain in found:
            domain_lower = domain.lower()
            if domain_lower in seen or domain_lower in whitelist:
                continue
            seen.add(domain_lower)

            suspicious = False
            reasons = []

            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.club',
                               '.work', '.bid', '.ru', '.cn']
            for tld in suspicious_tlds:
                if domain_lower.endswith(tld):
                    suspicious = True
                    reasons.append(f'Suspicious TLD: {tld}')
                    break

            if len(domain_lower) > 40:
                suspicious = True
                reasons.append('Very long domain - possible DGA')

            name_part = domain_lower.split('.')[0]
            if len(name_part) > 8:
                entropy = self._calculate_entropy(name_part)
                if entropy > 3.5:
                    suspicious = True
                    reasons.append(f'High entropy domain name ({entropy:.1f})')

            results.append({
                'domain': domain_lower,
                'suspicious': suspicious,
                'reasons': reasons,
                'occurrences': content.lower().count(domain_lower)
            })

        return results

    def _extract_hashes(self, content: str) -> List[Dict]:
        hash_patterns = {
            'md5': (r'\b[a-fA-F0-9]{32}\b', 32),
            'sha1': (r'\b[a-fA-F0-9]{40}\b', 40),
            'sha256': (r'\b[a-fA-F0-9]{64}\b', 64),
        }

        results = []
        seen = set()

        for hash_type, (pattern, expected_len) in hash_patterns.items():
            for match in re.finditer(pattern, content):
                value = match.group()
                if value in seen:
                    continue

                start = match.start()
                end = match.end()
                if start > 0 and content[start-1] in '0123456789abcdefABCDEF':
                    continue
                if end < len(content) and content[end] in '0123456789abcdefABCDEF':
                    continue

                seen.add(value)
                results.append({
                    'hash': value,
                    'type': hash_type,
                    'occurrences': content.count(value)
                })

        return results

    def _detect_c2_patterns(self, content: str) -> List[Dict]:
        findings = []

        for name, compiled in self._compiled_c2.items():
            matches = compiled.findall(content)
            if matches:
                info = self.C2_PATTERNS[name]
                unique_matches = list(set(matches[:20]))

                findings.append({
                    'pattern_name': name,
                    'description': info['description'],
                    'severity': info['severity'],
                    'mitre': info.get('mitre', ''),
                    'matches': unique_matches[:10],
                    'match_count': len(matches),
                })

        return findings

    def _detect_encoded_content(self, content: str) -> List[Dict]:
        findings = []

        for name, compiled in self._compiled_encoding.items():
            matches = compiled.findall(content)
            if matches:
                info = self.ENCODING_PATTERNS[name]

                decoded_samples = []
                if name == 'base64_block':
                    for m in matches[:5]:
                        try:
                            decoded = base64.b64decode(m).decode('utf-8', errors='ignore')
                            if decoded and len(decoded) > 3 and any(c.isalpha() for c in decoded):
                                decoded_samples.append({
                                    'encoded': m[:60] + '...' if len(m) > 60 else m,
                                    'decoded': decoded[:200]
                                })
                        except Exception:
                            pass

                findings.append({
                    'pattern_name': name,
                    'description': info['description'],
                    'severity': info['severity'],
                    'mitre': info.get('mitre', ''),
                    'match_count': len(matches),
                    'decoded_samples': decoded_samples,
                })

        return findings

    def _detect_credentials(self, content: str) -> List[Dict]:
        findings = []

        for name, compiled in self._compiled_creds.items():
            matches = compiled.findall(content)
            if matches:
                info = self.CREDENTIAL_PATTERNS[name]

                redacted = []
                for m in matches[:10]:
                    if isinstance(m, str) and len(m) > 20:
                        redacted.append(m[:15] + '***REDACTED***')
                    else:
                        redacted.append(str(m)[:30] + '...')

                findings.append({
                    'pattern_name': name,
                    'description': info['description'],
                    'severity': info['severity'],
                    'match_count': len(matches),
                    'samples': redacted[:5],
                })

        return findings

    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0

        freq = Counter(text)
        length = len(text)
        entropy = 0.0

        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy

    def _calculate_threat_score(self, analysis: Dict) -> Tuple[int, str, List[str]]:
        score = 0
        factors = []

        c2_findings = analysis.get('c2_patterns', [])
        for finding in c2_findings:
            severity = finding.get('severity', 'low')
            count = finding.get('match_count', 0)

            if severity == 'critical':
                score += min(40, count * 20)
                factors.append(f"CRITICAL: {finding['description']} ({count}x)")
            elif severity == 'high':
                score += min(25, count * 10)
                factors.append(f"HIGH: {finding['description']} ({count}x)")
            elif severity == 'medium':
                score += min(15, count * 5)
                factors.append(f"MEDIUM: {finding['description']} ({count}x)")

        ips = analysis.get('ip_addresses', [])
        suspicious_ips = [ip for ip in ips if ip.get('suspicious') and not ip.get('is_private')]
        external_ips = [ip for ip in ips if not ip.get('is_private')]

        if suspicious_ips:
            score += min(30, len(suspicious_ips) * 10)
            factors.append(f"{len(suspicious_ips)} suspicious external IPs")
        elif external_ips:
            score += min(15, len(external_ips) * 3)
            factors.append(f"{len(external_ips)} external IPs found")

        urls = analysis.get('urls', [])
        suspicious_urls = [u for u in urls if u.get('suspicious')]
        non_whitelisted = [u for u in urls if not u.get('is_whitelisted')]

        if suspicious_urls:
            score += min(25, len(suspicious_urls) * 8)
            factors.append(f"{len(suspicious_urls)} suspicious URLs")
        elif non_whitelisted:
            score += min(10, len(non_whitelisted) * 2)

        domains = analysis.get('domains', [])
        suspicious_domains = [d for d in domains if d.get('suspicious')]

        if suspicious_domains:
            score += min(20, len(suspicious_domains) * 7)
            factors.append(f"{len(suspicious_domains)} suspicious domains")

        hashes = analysis.get('hashes', [])
        if hashes:
            score += min(15, len(hashes) * 3)
            factors.append(f"{len(hashes)} file hashes found")

        encoded = analysis.get('encoded_content', [])
        for enc in encoded:
            severity = enc.get('severity', 'low')
            if severity == 'critical':
                score += 25
                factors.append(f"CRITICAL: {enc['description']}")
            elif severity == 'high':
                score += 15
                factors.append(f"HIGH: {enc['description']}")
            elif severity == 'medium':
                score += 5

        creds = analysis.get('credential_indicators', [])
        for cred in creds:
            severity = cred.get('severity', 'low')
            if severity == 'critical':
                score += 20
                factors.append(f"CRITICAL: {cred['description']}")
            elif severity == 'high':
                score += 10
                factors.append(f"HIGH: {cred['description']}")

        has_c2 = len(c2_findings) > 0
        has_suspicious_ip = len(suspicious_ips) > 0
        has_suspicious_url = len(suspicious_urls) > 0
        has_encoded = len(encoded) > 0
        has_creds = len(creds) > 0

        indicator_count = sum([has_c2, has_suspicious_ip, has_suspicious_url, has_encoded, has_creds])

        if indicator_count >= 4:
            score += 25
            factors.append("COMBO: 4+ indicator types detected (+25)")
        elif indicator_count >= 3:
            score += 15
            factors.append("COMBO: 3 indicator types detected (+15)")
        elif indicator_count >= 2:
            score += 8
            factors.append("COMBO: 2 indicator types detected (+8)")

        score = min(100, max(0, score))

        if score >= 70:
            verdict = 'MALICIOUS'
        elif score >= 40:
            verdict = 'SUSPICIOUS'
        else:
            verdict = 'CLEAN'

        return score, verdict, factors

    def analyze(self, file_path: str) -> Dict:
        logger.info(f"[TEXT] Analyzing text file: {Path(file_path).name}")

        try:
            path = Path(file_path)

            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except Exception as e:
                try:
                    with open(file_path, 'r', encoding='latin-1') as f:
                        content = f.read()
                except Exception as e2:
                    return {'error': f'Cannot read file: {e2}'}

            if not content or not content.strip():
                return {
                    'file_type': 'Text',
                    'analysis_tools': ['text_analyzer'],
                    'threat_indicators': [],
                    'note': 'Empty or blank file',
                    'threat_score': 0,
                }

            line_count = content.count('\n') + 1
            char_count = len(content)
            word_count = len(content.split())
            overall_entropy = self._calculate_entropy(content[:10000])

            ip_addresses = self._extract_ips(content)
            urls = self._extract_urls(content)
            domains = self._extract_domains(content)
            hashes = self._extract_hashes(content)

            c2_patterns = self._detect_c2_patterns(content)
            encoded_content = self._detect_encoded_content(content)
            credential_indicators = self._detect_credentials(content)

            email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
            emails = list(set(email_pattern.findall(content)))

            cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
            cves = list(set(cve_pattern.findall(content)))

            analysis = {
                'ip_addresses': ip_addresses,
                'urls': urls,
                'domains': domains,
                'hashes': hashes,
                'c2_patterns': c2_patterns,
                'encoded_content': encoded_content,
                'credential_indicators': credential_indicators,
                'emails': emails[:50],
                'cves': cves,
            }

            threat_score, verdict, contributing_factors = self._calculate_threat_score(analysis)

            iocs = {
                'urls': [u['url'] for u in urls if not u.get('is_whitelisted')],
                'ipv4': [ip['ip'] for ip in ip_addresses if not ip.get('is_private')],
                'domains': [d['domain'] for d in domains],
                'hashes': [h['hash'] for h in hashes],
                'emails': emails[:20],
                'cves': cves,
            }

            threat_indicators = []
            for finding in c2_patterns:
                threat_indicators.append(f"[{finding['severity'].upper()}] {finding['description']}")
            for ip in ip_addresses:
                if ip.get('suspicious'):
                    threat_indicators.append(f"[HIGH] Suspicious IP: {ip['ip']}" + (f":{ip['port']}" if ip.get('port') else ''))
            for url in urls:
                if url.get('suspicious'):
                    threat_indicators.append(f"[HIGH] Suspicious URL: {url['url'][:80]}")
            for enc in encoded_content:
                threat_indicators.append(f"[{enc['severity'].upper()}] {enc['description']}")
            for cred in credential_indicators:
                threat_indicators.append(f"[{cred['severity'].upper()}] {cred['description']}")

            mitre_techniques = []
            seen_mitre = set()
            for finding in c2_patterns:
                mitre_id = finding.get('mitre', '')
                if mitre_id and mitre_id not in seen_mitre:
                    mitre_techniques.append({
                        'technique_id': mitre_id,
                        'source': 'text_analysis',
                        'context': finding['description'],
                        'confidence': 'medium' if finding['severity'] in ('high', 'critical') else 'low'
                    })
                    seen_mitre.add(mitre_id)

            summary = {
                'total_ips': len(ip_addresses),
                'external_ips': len([ip for ip in ip_addresses if not ip.get('is_private')]),
                'suspicious_ips': len([ip for ip in ip_addresses if ip.get('suspicious')]),
                'total_urls': len(urls),
                'suspicious_urls': len([u for u in urls if u.get('suspicious')]),
                'total_domains': len(domains),
                'suspicious_domains': len([d for d in domains if d.get('suspicious')]),
                'total_hashes': len(hashes),
                'c2_patterns_found': len(c2_patterns),
                'encoded_content_found': len(encoded_content),
                'credentials_found': len(credential_indicators),
                'emails_found': len(emails),
                'cves_found': len(cves),
            }

            result = {
                'file_type': 'Text',
                'analysis_tools': ['text_analyzer'],
                'file_stats': {
                    'lines': line_count,
                    'characters': char_count,
                    'words': word_count,
                    'entropy': round(overall_entropy, 3),
                },
                'ip_addresses': ip_addresses,
                'urls': urls,
                'domains': domains,
                'hashes_found': hashes,
                'emails_found': emails[:50],
                'cves_found': cves,
                'c2_patterns': c2_patterns,
                'encoded_content': encoded_content,
                'credential_indicators': credential_indicators,
                'threat_indicators': threat_indicators,
                'mitre_techniques': mitre_techniques,
                'iocs': iocs,
                'summary': summary,
                'threat_score': threat_score,
                'verdict': verdict,
                'contributing_factors': contributing_factors,
                'suspicious_patterns': {
                    'total_matches': sum(f.get('match_count', 0) for f in c2_patterns),
                    'categories': {
                        f['pattern_name']: {
                            'count': f['match_count'],
                            'severity': f['severity']
                        } for f in c2_patterns
                    }
                },
                'suspicious_string_categories': [f['severity'].upper() for f in c2_patterns if f['severity'] in ('critical', 'high')],
            }

            logger.info(f"[TEXT] Analysis complete: {verdict} (score: {threat_score}/100)")
            logger.info(f"[TEXT] Found: {summary['total_ips']} IPs, {summary['total_urls']} URLs, "
                       f"{summary['total_domains']} domains, {summary['c2_patterns_found']} C2 patterns")

            return result

        except Exception as e:
            logger.error(f"[TEXT] Analysis failed: {e}", exc_info=True)
            return {
                'file_type': 'Text',
                'analysis_tools': ['text_analyzer'],
                'threat_indicators': [],
                'error': str(e),
                'threat_score': 0,
            }
