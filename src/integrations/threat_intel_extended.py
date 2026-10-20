"""
Author: Ugur AtesExtended threat intelligence sources (20+ total)."""

import aiohttp
import asyncio
import json
from typing import Dict
import logging
from urllib.parse import quote
from ..utils.api_key_validator import get_valid_key

logger = logging.getLogger(__name__)
class ThreatIntelExtended:
    """Additional threat intelligence sources to reach 20+."""
    
    def __init__(self, config: Dict):
        self.config = config
        self.api_keys = config.get('api_keys', {})
        self.timeout = aiohttp.ClientTimeout(total=30)
    
    async def check_greynoise(self, ip: str) -> Dict:
        """GreyNoise - Internet scanner detection."""
        api_key = self.api_keys.get('greynoise', '')
        if not api_key:
            return {'source': 'GreyNoise', 'status': '⚠', 'error': 'No valid API key configured', 'found': False}
        
        try:
            url = f'https://api.greynoise.io/v3/community/{ip}'
            headers = {'key': api_key}
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            'source': 'GreyNoise',
                            'found': data.get('riot', False) or data.get('noise', False),
                            'classification': data.get('classification', 'unknown'),
                            'name': data.get('name', ''),
                            'last_seen': data.get('last_seen', ''),
                            'status': '✓' if data.get('noise') else '✗'
                        }
            return {'source': 'GreyNoise', 'status': '⚠', 'error': 'Error', 'found': False}
        except Exception as e:
            logger.error(f"[GreyNoise] Error: {e}")
            return {'source': 'GreyNoise', 'status': '⚠', 'error': str(e), 'found': False}
    
    async def check_censys(self, ioc: str, ioc_type: str) -> Dict:
        """Censys - Internet-wide scanning data."""
        api_key = get_valid_key(self.api_keys, 'censys')
        if not api_key:
            return {'source': 'Censys', 'status': '⚠', 'error': 'No valid API key configured', 'found': False}
        
        try:
            if ioc_type == 'ipv4':
                url = f'https://api.platform.censys.io/v3/global/asset/host/{ioc}'
            else:
                return {'source': 'Censys', 'status': '⚠', 'error': 'Unsupported type', 'found': False}
            
            headers = {'Authorization': f'Bearer {api_key}'}
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        result = data.get('result', {}).get('resource', {})
                        return {
                            'source': 'Censys',
                            'found': True,
                            'services': len(result.get('services', [])),
                            'location': result.get('location', {}).get('country', 'Unknown'),
                            'autonomous_system': result.get('autonomous_system', {}).get('name', 'Unknown'),
                            'status': '➖'
                        }
            return {'source': 'Censys', 'status': 'Not found', 'found': False}
        except Exception as e:
            logger.error(f"[Censys] Error: {e}")
            return {'source': 'Censys', 'status': '⚠', 'error': str(e), 'found': False}
    
    async def check_talos(self, ip: str) -> Dict:
        """
        Talos Intelligence (Cisco) - IP reputation via SenderBase SBRS.

        Uses DNS-based SenderBase reputation lookup (free, no API key needed).
        Query: reversed-IP.query.senderbase.org -> TXT record contains SBRS score.
        SBRS range: -10 (worst) to +10 (best).
        """
        try:
            import re
            # Only works for IPv4
            if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                return {
                    'source': 'Talos Intelligence',
                    'status': '⚠',
                    'error': 'Only IPv4 supported',
                    'found': False,
                    'url': f'https://talosintelligence.com/reputation_center/lookup?search={ip}',
                }

            # Reverse the IP octets for DNS query
            reversed_ip = '.'.join(ip.split('.')[::-1])
            dns_query = f'{reversed_ip}.query.senderbase.org'

            import asyncio
            try:
                import dns.resolver
                resolver = dns.resolver.Resolver()
                resolver.timeout = 5
                resolver.lifetime = 5
                answers = resolver.resolve(dns_query, 'TXT')

                sbrs_score = None
                raw_txt = ''
                for rdata in answers:
                    raw_txt = str(rdata).strip('"')
                    # Format: "nn=X.Y|..."  where nn=SBRS score
                    for part in raw_txt.split('|'):
                        if '=' in part:
                            key, _, val = part.partition('=')
                            if key.strip() == 'nn':
                                try:
                                    sbrs_score = float(val.strip())
                                except ValueError:
                                    pass

                if sbrs_score is not None:
                    # Map SBRS (-10..+10) to threat score (0..100)
                    # -10 -> 100, 0 -> 50, +10 -> 0
                    threat_score = max(0, min(100, int(50 - (sbrs_score * 5))))
                    is_flagged = sbrs_score < -2

                    return {
                        'source': 'Talos Intelligence',
                        'found': True,
                        'sbrs_score': sbrs_score,
                        'score': threat_score,
                        'status': '✓' if is_flagged else '✗',
                        'message': f'SBRS score: {sbrs_score} ({"Poor" if sbrs_score < -2 else "Neutral" if sbrs_score < 3 else "Good"})',
                        'url': f'https://talosintelligence.com/reputation_center/lookup?search={ip}',
                    }
                else:
                    return {
                        'source': 'Talos Intelligence',
                        'found': False,
                        'status': '✗',
                        'message': f'DNS response without SBRS: {raw_txt}',
                        'url': f'https://talosintelligence.com/reputation_center/lookup?search={ip}',
                    }

            except ImportError:
                logger.warning("[Talos] dnspython not available for SBRS lookup")
                return {
                    'source': 'Talos Intelligence',
                    'status': '⚠',
                    'error': 'dnspython required',
                    'found': False,
                    'url': f'https://talosintelligence.com/reputation_center/lookup?search={ip}',
                }
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                return {
                    'source': 'Talos Intelligence',
                    'found': False,
                    'status': '✗',
                    'message': 'No SBRS record found',
                    'url': f'https://talosintelligence.com/reputation_center/lookup?search={ip}',
                }
            except dns.exception.Timeout:
                return {
                    'source': 'Talos Intelligence',
                    'found': False,
                    'status': '⚠',
                    'message': 'SenderBase SBRS DNS timed out (service may be deprecated)',
                    'url': f'https://talosintelligence.com/reputation_center/lookup?search={ip}',
                }

        except Exception as e:
            logger.error(f"[Talos] Error: {e}")
            return {'source': 'Talos Intelligence', 'status': '⚠', 'error': str(e), 'found': False}
    
    async def check_pulsedive(self, ioc: str) -> Dict:
        """Pulsedive - Community threat intelligence."""
        api_key = self.api_keys.get('pulsedive', '')
        if not api_key:
            return {'source': 'Pulsedive', 'status': '⚠', 'error': 'No valid API key configured', 'found': False}
        
        try:
            url = f'https://pulsedive.com/api/info.php'
            params = {'indicator': ioc, 'key': api_key}
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            'source': 'Pulsedive',
                            'found': True,
                            'risk': data.get('risk', 'unknown'),
                            'threats': data.get('threats', []),
                            'stamp_seen': data.get('stamp_seen', ''),
                            'status': '✓' if data.get('risk') in ['high', 'critical'] else '✗'
                        }
            return {'source': 'Pulsedive', 'status': 'Not found', 'found': False}
        except Exception as e:
            logger.error(f"[Pulsedive] Error: {e}")
            return {'source': 'Pulsedive', 'status': '⚠', 'error': str(e), 'found': False}
    
    async def check_criminalip(self, ip: str) -> Dict:
        """Criminal IP - Threat scoring."""
        api_key = self.api_keys.get('criminalip', '')
        if not api_key:
            return {'source': 'Criminal IP', 'status': '⚠', 'error': 'No valid API key configured', 'found': False}
        
        try:
            url = f'https://api.criminalip.io/v1/ip/scan/{ip}'
            headers = {'x-api-key': api_key}
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            'source': 'Criminal IP',
                            'found': True,
                            'score': data.get('score', 0),
                            'country': data.get('country', 'Unknown'),
                            'is_vpn': data.get('is_vpn', False),
                            'is_proxy': data.get('is_proxy', False),
                            'status': '✓' if data.get('score', 0) > 50 else '✗'
                        }
            return {'source': 'Criminal IP', 'status': 'Not found', 'found': False}
        except Exception as e:
            logger.error(f"[Criminal IP] Error: {e}")
            return {'source': 'Criminal IP', 'status': '⚠', 'error': str(e), 'found': False}
    
    async def check_ipqualityscore(self, ip: str) -> Dict:
        """IPQualityScore - Fraud detection."""
        api_key = self.api_keys.get('ipqualityscore', '')
        if not api_key:
            return {'source': 'IPQualityScore', 'status': '⚠', 'error': 'No valid API key configured', 'found': False}
        
        try:
            url = f'https://ipqualityscore.com/api/json/ip/{api_key}/{ip}'
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            'source': 'IPQualityScore',
                            'found': True,
                            'fraud_score': data.get('fraud_score', 0),
                            'proxy': data.get('proxy', False),
                            'vpn': data.get('vpn', False),
                            'tor': data.get('tor', False),
                            'bot_status': data.get('bot_status', False),
                            'status': '✓' if data.get('fraud_score', 0) > 75 else '✗'
                        }
            return {'source': 'IPQualityScore', 'status': 'Not found', 'found': False}
        except Exception as e:
            logger.error(f"[IPQualityScore] Error: {e}")
            return {'source': 'IPQualityScore', 'status': '⚠', 'error': str(e), 'found': False}
    
    async def check_spamhaus(self, ip: str) -> Dict:
        """Spamhaus - Spam/malware tracking."""
        # Only 127.0.0.2 through 127.0.0.11 are listing codes. In particular,
        # 127.255.255.252/.254/.255 are resolver/query errors, not listings.
        # 2026-09-21: DNS resolve สำเร็จเมื่อใดก็ set found=True โดยไม่แยก return code. PBL 127.0.0.10/11
        # เป็นนโยบายอีเมล ไม่ใช่สัญญาณ malware; แต่ status นี้ถูกนับใน scoring เท่า SBL. tests ปัจจุบัน mock
        # เฉพาะ dispatch ไม่มี test ตรวจ code. หลักฐาน: evidence/source_weights_2026-09-21/spamhaus_codes_group_a_2026-09-21.jsonl และ
        # docs/SOCPOW_scope_ledger.md หัวข้อ 3.
        try:
            # Spamhaus uses DNSBL
            import socket
            reversed_ip = '.'.join(reversed(ip.split('.')))
            query = f'{reversed_ip}.zen.spamhaus.org'
            
            try:
                answer = socket.gethostbyname(query)
            except socket.gaierror as e:
                if e.errno == socket.EAI_NONAME:
                    return {
                        'source': 'Spamhaus',
                        'found': False,
                        'listed': False,
                        'status': '\u2717'
                    }
                return {
                    'source': 'Spamhaus',
                    'found': False,
                    'status': '\u26a0',
                    'error': f'DNS resolver error: {e}',
                    'unavailable': True,
                }

            octets = answer.split('.')
            if (
                len(octets) == 4
                and octets[:3] == ['127', '0', '0']
                and octets[3].isdigit()
                and 2 <= int(octets[3]) <= 11
            ):
                return {
                    'source': 'Spamhaus',
                    'found': True,
                    'listed': True,
                    'status': '\u2713'
                }
            return {
                'source': 'Spamhaus',
                'found': False,
                'status': '\u26a0',
                'error': f'Unexpected Spamhaus DNSBL answer: {answer}',
                'unavailable': True,
            }
        except Exception as e:
            logger.error(f"[Spamhaus] Error: {e}")
            return {
                'source': 'Spamhaus',
                'status': '\u26a0',
                'error': str(e),
                'found': False,
                'unavailable': True,
            }
    
    async def check_phishtank(self, url: str) -> Dict:
        """PhishTank - Phishing URL database."""
        api_key = self.api_keys.get('phishtank', '')
        if not api_key:
            return {'source': 'PhishTank', 'status': '⚠', 'error': 'No valid API key configured', 'found': False}
        
        try:
            import urllib.parse
            check_url = 'https://checkurl.phishtank.com/checkurl/'
            data = {
                'url': urllib.parse.quote(url),
                'format': 'json',
                'app_key': api_key
            }
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(check_url, data=data) as response:
                    if response.status == 200:
                        result = await response.json()
                        in_database = result.get('results', {}).get('in_database', False)
                        return {
                            'source': 'PhishTank',
                            'found': in_database,
                            'verified': result.get('results', {}).get('verified', False),
                            'phish_id': result.get('results', {}).get('phish_id', ''),
                            'status': '✓' if in_database else '✗'
                        }
            return {'source': 'PhishTank', 'status': 'Not found', 'found': False}
        except Exception as e:
            logger.error(f"[PhishTank] Error: {e}")
            return {'source': 'PhishTank', 'status': '⚠', 'error': str(e), 'found': False}
    
    async def check_circl(self, ioc: str) -> Dict:
        """CIRCL - Passive DNS/SSL."""
        try:
            # CIRCL's current Passive DNS API is partner-restricted and
            # returns Passive DNS Common Output as newline-delimited JSON.
            url = f'https://www.circl.lu/pdns/query/{quote(ioc, safe="")}'
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        body = await response.text()
                        data = []
                        for line in body.splitlines():
                            line = line.strip()
                            if line:
                                data.append(json.loads(line))
                        return {
                            'source': 'CIRCL',
                            'found': len(data) > 0,
                            'records': len(data),
                            'status': '✓' if len(data) > 0 else '✗'
                        }
                    result = {
                        'source': 'CIRCL',
                        'status': chr(0x26A0),
                        'error': f'HTTP {response.status}',
                        'found': False,
                    }
                    return result
        except Exception as e:
            logger.error(f"[CIRCL] Error: {e}")
            return {'source': 'CIRCL', 'status': '⚠', 'error': str(e), 'found': False}
    
    async def check_ip2proxy(self, ip: str) -> Dict:
        """
        IP2Proxy - VPN/Proxy/Tor detection service.
        
        Proxy Types: VPN, TOR, DCH (Data Center), PUB (Public Proxy),
                     WEB (Web Proxy), SES (Search Engine Spider), RES (Residential)
        
        API Documentation: https://www.ip2proxy.com/web-service
        """
        api_key = self.api_keys.get('ip2proxy', '')
        if not api_key:
            return {'source': 'IP2Proxy', 'status': '⚠', 'error': 'No API key', 'found': False}
        
        try:
            url = f'https://api.ip2proxy.com/?ip={ip}&key={api_key}&package=PX11'
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if data.get('response') == 'OK':
                            is_proxy = data.get('isProxy', 'NO') == 'YES'
                            proxy_type = data.get('proxyType', '-')
                            
                            # Proxy type analysis
                            is_vpn = proxy_type == 'VPN'
                            is_tor = proxy_type == 'TOR'
                            is_datacenter = proxy_type == 'DCH'
                            is_public = proxy_type == 'PUB'
                            
                            # Calculate score
                            score = 0
                            if is_tor:
                                score = 70
                            elif is_vpn:
                                score = 40
                            elif is_datacenter:
                                score = 30
                            elif is_public:
                                score = 35
                            elif is_proxy:
                                score = 25
                            
                            return {
                                'source': 'IP2Proxy',
                                'status': '✓' if is_proxy else '✗',
                                'found': is_proxy,
                                'is_proxy': is_proxy,
                                'is_vpn': is_vpn,
                                'is_tor': is_tor,
                                'is_datacenter': is_datacenter,
                                'proxy_type': proxy_type,
                                'country': data.get('countryCode', '-'),
                                'region': data.get('regionName', '-'),
                                'city': data.get('cityName', '-'),
                                'isp': data.get('isp', '-'),
                                'domain': data.get('domain', '-'),
                                'usage_type': data.get('usageType', '-'),
                                'threat': data.get('threat', '-'),
                                'score': score
                            }
                        else:
                            return {
                                'source': 'IP2Proxy',
                                'status': '⚠',
                                'error': data.get('response', 'Error'),
                                'found': False
                            }
            return {'source': 'IP2Proxy', 'status': '⚠', 'error': 'Request failed', 'found': False}
                        
        except asyncio.TimeoutError:
            return {'source': 'IP2Proxy', 'status': '⚠', 'error': 'Timeout', 'found': False}
        except Exception as e:
            logger.error(f"[IP2Proxy] Error: {e}")
            return {'source': 'IP2Proxy', 'status': '⚠', 'error': str(e), 'found': False}
    
    async def check_triage(self, file_hash: str) -> Dict:
        """
        Tria.ge (Hatching) - Automated malware sandbox.
        
        API Documentation: https://tria.ge/docs/cloud-api/
        """
        api_key = self.api_keys.get('triage', '')
        if not api_key:
            return {'source': 'Triage', 'status': '⚠', 'error': 'No API key', 'found': False}
        
        try:
            headers = {
                'Authorization': f'Bearer {api_key}',
                'Accept': 'application/json'
            }
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                # Search for sample by hash
                search_url = f'https://api.tria.ge/v0/search?query=sha256:{file_hash}'
                
                async with session.get(search_url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if data.get('data') and len(data['data']) > 0:
                            sample = data['data'][0]
                            sample_id = sample.get('id', '')
                            
                            # Get detailed analysis
                            if sample_id:
                                detail_url = f'https://api.tria.ge/v0/samples/{sample_id}/overview.json'
                                
                                async with session.get(detail_url, headers=headers) as detail_resp:
                                    if detail_resp.status == 200:
                                        analysis = await detail_resp.json()
                                        
                                        # Extract key info
                                        families = analysis.get('family', [])
                                        triage_score = analysis.get('score', 0)
                                        tags = analysis.get('tags', [])
                                        signatures = [s.get('name') for s in analysis.get('signatures', []) if isinstance(s, dict)][:20]
                                        
                                        # Network indicators - handle both dict and list formats
                                        targets = analysis.get('targets', {})
                                        domains = []
                                        ips = []
                                        urls = []
                                        
                                        if isinstance(targets, dict):
                                            domains = targets.get('domains', [])[:10]
                                            ips = targets.get('ips', [])[:10]
                                            urls = targets.get('urls', [])[:10]
                                        elif isinstance(targets, list):
                                            # targets is a list of target objects
                                            for t in targets[:5]:
                                                if isinstance(t, dict):
                                                    if t.get('iocs'):
                                                        iocs = t.get('iocs', {})
                                                        if isinstance(iocs, dict):
                                                            domains.extend(iocs.get('domains', [])[:5])
                                                            ips.extend(iocs.get('ips', [])[:5])
                                                            urls.extend(iocs.get('urls', [])[:5])
                                        
                                        return {
                                            'source': 'Triage',
                                            'status': '✓',
                                            'found': True,
                                            'sample_id': sample_id,
                                            'family': families if isinstance(families, list) else [families] if families else [],
                                            'score': triage_score,
                                            'tags': tags if isinstance(tags, list) else [],
                                            'signatures': signatures,
                                            'network': {
                                                'domains': domains[:10],
                                                'ips': ips[:10],
                                                'urls': urls[:10]
                                            },
                                            'link': f'https://tria.ge/{sample_id}'
                                        }
                            
                            return {
                                'source': 'Triage',
                                'status': '✓',
                                'found': True,
                                'sample_id': sample_id,
                                'link': f'https://tria.ge/{sample_id}'
                            }
                        
                        return {'source': 'Triage', 'status': '✗', 'found': False}
                        
                    elif response.status == 404:
                        return {'source': 'Triage', 'status': '✗', 'found': False}
                    else:
                        return {'source': 'Triage', 'status': '⚠', 'error': f'HTTP {response.status}', 'found': False}
                        
        except asyncio.TimeoutError:
            return {'source': 'Triage', 'status': '⚠', 'error': 'Timeout', 'found': False}
        except Exception as e:
            logger.error(f"[Triage] Error: {e}")
            return {'source': 'Triage', 'status': '⚠', 'error': str(e), 'found': False}
    
    async def check_threatzone(self, file_hash: str) -> Dict:
        """
        Threat.Zone - Cloud-based malware sandbox.
        
        API Documentation: https://app.threat.zone/docs
        
        Features:
        - Static + Dynamic analysis
        - Network IOCs extraction
        - MITRE ATT&CK mapping
        - Malware family detection
        """
        api_key = self.api_keys.get('threatzone', '')
        if not api_key:
            return {'source': 'Threat.Zone', 'status': '⚠', 'error': 'No API key', 'found': False}
        
        try:
            headers = {
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                # Search for sample by hash
                search_url = f'https://app.threat.zone/api/v1/search'
                search_data = {
                    'query': file_hash,
                    'type': 'sha256'
                }
                
                async with session.post(search_url, headers=headers, json=search_data) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        results = data.get('results', [])
                        if results and len(results) > 0:
                            sample = results[0]
                            submission_id = sample.get('id', '')
                            
                            # Get detailed report
                            if submission_id:
                                report_url = f'https://app.threat.zone/api/v1/submission/{submission_id}/report'
                                
                                async with session.get(report_url, headers=headers) as report_resp:
                                    if report_resp.status == 200:
                                        report = await report_resp.json()
                                        
                                        # Extract analysis info
                                        verdict = report.get('verdict', 'unknown')
                                        threat_level = report.get('threat_level', 0)
                                        malware_family = report.get('malware_family', [])
                                        
                                        # MITRE ATT&CK techniques
                                        mitre = report.get('mitre_attack', {})
                                        techniques = [t.get('technique_id') for t in mitre.get('techniques', [])]
                                        
                                        # Network indicators
                                        network = report.get('network', {})
                                        domains = network.get('domains', [])[:10]
                                        ips = network.get('ips', [])[:10]
                                        urls = network.get('urls', [])[:10]
                                        
                                        # Behaviors
                                        behaviors = report.get('behaviors', [])
                                        signatures = [b.get('description', '') for b in behaviors][:15]
                                        
                                        # Calculate score (0-100)
                                        score = 0
                                        if verdict == 'malicious':
                                            score = 90 + min(10, threat_level)
                                        elif verdict == 'suspicious':
                                            score = 50 + threat_level
                                        elif verdict == 'clean':
                                            score = 0
                                        
                                        return {
                                            'source': 'Threat.Zone',
                                            'status': '✓',
                                            'found': True,
                                            'submission_id': submission_id,
                                            'verdict': verdict,
                                            'threat_level': threat_level,
                                            'malware_family': malware_family,
                                            'mitre_techniques': techniques[:20],
                                            'signatures': signatures,
                                            'network': {
                                                'domains': domains,
                                                'ips': ips,
                                                'urls': urls
                                            },
                                            'score': score,
                                            'link': f'https://app.threat.zone/submission/{submission_id}'
                                        }
                            
                            return {
                                'source': 'Threat.Zone',
                                'status': '✓',
                                'found': True,
                                'submission_id': submission_id,
                                'link': f'https://app.threat.zone/submission/{submission_id}'
                            }
                        
                        return {'source': 'Threat.Zone', 'status': '✗', 'found': False}
                    
                    elif response.status == 401:
                        return {'source': 'Threat.Zone', 'status': '⚠', 'error': 'Invalid API key', 'found': False}
                    elif response.status == 404:
                        return {'source': 'Threat.Zone', 'status': '✗', 'found': False}
                    else:
                        return {'source': 'Threat.Zone', 'status': '⚠', 'error': f'HTTP {response.status}', 'found': False}
                        
        except asyncio.TimeoutError:
            return {'source': 'Threat.Zone', 'status': '⚠', 'error': 'Timeout', 'found': False}
        except Exception as e:
            logger.error(f"[Threat.Zone] Error: {e}")
            return {'source': 'Threat.Zone', 'status': '⚠', 'error': str(e), 'found': False}
