"""
Author: Ugur AtesDetection rule generator for multiple SIEM/EDR platforms."""

from typing import Dict, List
import hashlib
import logging
import re
import uuid

import yaml

from src.branding import BRAND_NAME


class _SigmaDumper(yaml.SafeDumper):
    """Indent list items under keys like the existing Sigma output."""

    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow, False)


class _SingleQuoted(str):
    """Value that should always be emitted as a single-quoted YAML scalar."""


def _represent_single_quoted(dumper, data):
    return dumper.represent_scalar(
        'tag:yaml.org,2002:str', str(data), style="'"
    )


_SigmaDumper.add_representer(_SingleQuoted, _represent_single_quoted)

logger = logging.getLogger(__name__)
class RuleGenerator:
    """
    Generate detection rules for multiple platforms.
    
    IOC generation supports:
    - KQL (Microsoft Defender/Sentinel)
    - SPL (Splunk)
    - SIGMA (Universal)
    - XQL (Cortex XDR)
    - DQL (Google SecOps)
    - Suricata
    - Firewall
    """
    
    @staticmethod
    def generate_ioc_rules(ioc: str, ioc_type: str, context: Dict = None) -> Dict[str, str]:
        """
        Generate detection rules for IOC.
        
        Args:
            ioc: Indicator of Compromise
            ioc_type: Type (ipv4, domain, url, hash)
            context: Additional context (malware family, etc.)
        
        Returns:
            Dict containing seven IOC rules: KQL, SPL, Sigma, XQL, DQL,
            Suricata, and Firewall.
        """
        rules = {
            'kql': RuleGenerator._generate_kql_ioc(ioc, ioc_type, context),
            'spl': RuleGenerator._generate_spl_ioc(ioc, ioc_type, context),
            'sigma': RuleGenerator._generate_sigma_ioc(ioc, ioc_type, context),
            'xql': RuleGenerator._generate_xql_ioc(ioc, ioc_type, context),
            'dql': RuleGenerator._generate_dql_ioc(ioc, ioc_type, context),
            'suricata': RuleGenerator._generate_suricata_ioc(ioc, ioc_type, context),
            'firewall': RuleGenerator._generate_firewall_ioc(ioc, ioc_type, context),
        }

        if context and str(context.get('verdict', 'Unknown')).strip().upper() == 'CLEAN':
            rules.pop('firewall', None)

        value = rules.get('firewall')
        if isinstance(value, str) and not any(
            line.strip() and not line.lstrip().startswith('#')
            for line in value.splitlines()
        ):
            rules.pop('firewall', None)
        
        return rules
    
    @staticmethod
    def generate_file_rules(file_data: Dict) -> Dict[str, str]:
        """
        Generate detection rules for malicious file.
        
        Args:
            file_data: File analysis results
        
        Returns:
            Dict with rules for each platform
        """
        rules = {
            'kql': RuleGenerator._generate_kql_file(file_data),
            'spl': RuleGenerator._generate_spl_file(file_data),
            'yara': RuleGenerator._generate_yara_file(file_data),
            'sigma': RuleGenerator._generate_sigma_file(file_data)
        }
        
        return rules

    @staticmethod
    def generate_capa_rules(capa_summary: dict) -> dict:
        """Generate reference YARA and Sigma rules from a capa summary."""
        capabilities = capa_summary.get('capabilities', [])
        mitre_attacks = capa_summary.get('mitre_attacks', [])

        if not capabilities and not mitre_attacks:
            return {
                "error": (
                    "No capa capabilities or MITRE techniques found in "
                    "analysis_result."
                )
            }

        source_file = str(capa_summary.get('file', ''))

        def escape_quoted(value: object) -> str:
            return str(value).replace('\\', '\\\\').replace('"', '\\"')

        yara_rules = []
        for index, capability in enumerate(capabilities, start=1):
            name = str(capability.get('name', 'unknown capability'))
            namespace = str(capability.get('namespace', ''))
            scope = str(capability.get('scope', ''))
            identifier = re.sub(r'[^A-Za-z0-9_]', '_', name).strip('_')
            identifier = re.sub(r'_+', '_', identifier) or 'Unknown_Capability'
            if identifier[0].isdigit():
                identifier = f'Capability_{identifier}'

            yara_rules.append(
                f'''rule Capa_{identifier}_{index} {{
    meta:
        description = "Reference rule for capa capability: {escape_quoted(name)}"
        capability = "{escape_quoted(name)}"
        namespace = "{escape_quoted(namespace)}"
        scope = "{escape_quoted(scope)}"
        source_file = "{escape_quoted(source_file)}"
    condition:
        true
}}'''
            )

        sigma_rules = []
        for attack in mitre_attacks:
            technique = str(attack.get('technique', 'Unknown Technique'))
            attack_id = str(attack.get('id', ''))
            tactic = str(attack.get('tactic', 'Unknown Tactic'))
            stable_id = hashlib.sha256(
                f'{attack_id}|{technique}|{tactic}|{source_file}'.encode('utf-8')
            ).hexdigest()[:12]
            tag = re.sub(r'[^a-z0-9._-]', '', attack_id.lower())
            tags = f'\ntags:\n    - attack.{tag}' if tag else ''
            source_name = source_file.replace('\\', '/').rsplit('/', 1)[-1]

            sigma_rules.append(
                f'''title: "capa - {escape_quoted(tactic)} - {escape_quoted(technique)}"
id: capa-{stable_id}
status: experimental
description: "Reference detection for capa MITRE technique {escape_quoted(technique)} ({escape_quoted(attack_id)}) in tactic {escape_quoted(tactic)}."
references:
    - https://github.com/mandiant/capa{tags}
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: "{escape_quoted(source_name)}"
    condition: selection
falsepositives:
    - Legitimate software exhibiting the mapped capability
level: medium'''
            )

        return {'yara': yara_rules, 'sigma': sigma_rules}
    
    @staticmethod
    def _generate_kql_ioc(ioc: str, ioc_type: str, context: Dict) -> str:
        """Generate KQL rule for IOC."""
        if ioc_type == 'ipv4':
            return f"""// KQL - Hunt for IP: {ioc}
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "{ioc}" or InitiatingProcessFileName == "{ioc}"
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| summarize count() by DeviceName, RemoteIP"""
        
        elif ioc_type == 'domain':
            return f"""// KQL - Hunt for Domain: {ioc}
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "{ioc}"
| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName
| summarize count() by DeviceName, RemoteUrl"""
        
        elif ioc_type in ('hash', 'md5', 'sha1', 'sha256'):
            return f"""// KQL - Hunt for Hash: {ioc}
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 == "{ioc}" or SHA1 == "{ioc}" or MD5 == "{ioc}"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256
| summarize count() by DeviceName, FileName"""
        
        elif ioc_type == 'url':
            return f"""// KQL - Hunt for URL: {ioc}
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl == "{ioc}"
| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName"""
        
        return "// KQL - IOC type not supported"
    
    @staticmethod
    def _generate_spl_ioc(ioc: str, ioc_type: str, context: Dict) -> str:
        """Generate SPL rule for IOC."""
        if ioc_type == 'ipv4':
            return f"""# SPL - Hunt for IP: {ioc}
index=* earliest=-30d
| search dest_ip="{ioc}" OR src_ip="{ioc}"
| stats count by host, dest_ip, src_ip, dest_port"""
        
        elif ioc_type == 'domain':
            return f"""# SPL - Hunt for Domain: {ioc}
index=* earliest=-30d
| search url="*{ioc}*" OR domain="*{ioc}*"
| stats count by host, url, domain"""
        
        elif ioc_type in ('hash', 'md5', 'sha1', 'sha256'):
            return f"""# SPL - Hunt for Hash: {ioc}
index=* earliest=-30d
| search hash="{ioc}" OR sha256="{ioc}" OR md5="{ioc}"
| stats count by host, file_name, file_path, hash"""
        
        return "# SPL - IOC type not supported"
    
    @staticmethod
    def _generate_sigma_ioc(ioc: str, ioc_type: str, context: Dict) -> str:
        """Generate complete SIGMA rule for IOC using safe YAML serialization."""
        from datetime import datetime

        ioc = str(ioc)
        malware_family = (
            str(context.get('malware_family', 'Unknown'))
            if context else 'Unknown'
        )
        verdict = str(context.get('verdict', 'Unknown')) if context else 'Unknown'
        is_clean = str(verdict).strip().upper() == 'CLEAN'

        level = (
            'informational' if is_clean
            else 'critical' if verdict == 'MALICIOUS'
            else 'high' if verdict == 'SUSPICIOUS'
            else 'medium'
        )
        rule_id = uuid.uuid5(uuid.NAMESPACE_URL, f"{ioc_type}:{ioc}")
        value = _SingleQuoted(ioc)

        rule = {
            'title': (
                f'Hunt for {ioc} (verdict CLEAN)'
                if is_clean else f'Detection of {malware_family} IOC - {ioc}'
            ),
            'id': str(rule_id),
            'status': 'experimental',
            'description': (
                f'Hunt for activity related to {ioc}; verdict CLEAN, informational only'
                if is_clean
                else f'Detects network activity related to {verdict} IOC'
            ),
            'author': 'Ugur Ates',
            'date': datetime.now().strftime('%Y-%m-%d'),
            'references': ['https://github.com/ugur-ates/blue-team-assistant'],
            'tags': [] if is_clean else ['attack.command-and-control', 'attack.t1071'],
        }

        if ioc_type == 'ipv4':
            rule['logsource'] = {'category': 'firewall'}
            rule['detection'] = {
                'selection_dst': {'dst_ip': value},
                'selection_src': {'src_ip': value},
                'condition': 'selection_dst or selection_src',
            }
            rule['fields'] = ['src_ip', 'dst_ip', 'dst_port', 'action']
        elif ioc_type == 'domain':
            rule['logsource'] = {'category': 'dns'}
            rule['detection'] = {
                'selection': {'query|contains': value},
                'condition': 'selection',
            }
            rule['fields'] = ['query', 'answer', 'src_ip']
        elif ioc_type == 'url':
            rule['logsource'] = {'category': 'proxy'}
            rule['detection'] = {
                'selection': {'c-uri|contains': value},
                'condition': 'selection',
            }
            rule['fields'] = ['c-uri', 'cs-host', 'src_ip']
        elif ioc_type in ['sha256', 'md5', 'sha1', 'hash']:
            rule['logsource'] = {'category': 'file_event', 'product': 'windows'}
            rule['detection'] = {
                'selection': {'Hashes|contains': value},
                'condition': 'selection',
            }
            rule['fields'] = ['TargetFilename', 'Hashes', 'User']
        else:
            # Generic fallback
            rule['logsource'] = {'category': 'network_connection'}
            rule['detection'] = {
                'selection': [
                    {'dst_ip': value},
                    {'query': value},
                    {'url|contains': value},
                ],
                'condition': 'selection',
            }

        rule['falsepositives'] = ['Legitimate traffic to this destination']
        rule['level'] = level

        return yaml.dump(
            rule,
            Dumper=_SigmaDumper,
            sort_keys=False,
            allow_unicode=True,
            default_flow_style=False,
            indent=4,
            width=1_000_000,
        )
    
    @staticmethod
    def _generate_xql_ioc(ioc: str, ioc_type: str, context: Dict) -> str:
        """Generate XQL rule for IOC."""
        if ioc_type == 'ipv4':
            return f"""// XQL - Hunt for IP: {ioc}
dataset = xdr_data
| filter event_type = NETWORK_CONNECTION and remote_ip = "{ioc}"
| fields agent_hostname, remote_ip, remote_port, process_name
| limit 100"""
        
        elif ioc_type == 'domain':
            return f"""// XQL - Hunt for Domain: {ioc}
dataset = xdr_data
| filter event_type = DNS_QUERY and dns_query_name contains "{ioc}"
| fields agent_hostname, dns_query_name, process_name
| limit 100"""

        elif ioc_type in ('hash', 'md5', 'sha1', 'sha256'):
            return f"""// XQL - Hunt for File Hash: {ioc}
dataset = xdr_data
| filter event_type = FILE and (action_file_sha256 = "{ioc}" or action_file_sha1 = "{ioc}" or action_file_md5 = "{ioc}")
| fields agent_hostname, action_file_name, action_file_path, action_file_sha256, action_file_sha1, action_file_md5, actor_process_image_name
| limit 100"""
        
        return "// XQL - IOC type not supported"

    @staticmethod
    def _generate_dql_ioc(ioc: str, ioc_type: str, context: Dict) -> str:
        """Generate DQL (OpenSearch Dashboards Query Language, used by the
        Wazuh indexer/dashboard) for an IOC. Field names below are
        best-effort guesses at common Wazuh alert field names (e.g. Sysmon
        decoder fields) — SOCPOW does not yet have a live Wazuh ingestion
        pipeline to verify exact field mappings against, so this is a
        reference query format, not a verified-live query."""
        if ioc_type in ('ipv4', 'ip'):
            return (
                f'// DQL (Wazuh/OpenSearch) - Hunt for IP: {ioc}\n'
                f'srcip:"{ioc}" or data.win.eventdata.destinationIp:"{ioc}"'
            )
        elif ioc_type == 'domain':
            return (
                f'// DQL (Wazuh/OpenSearch) - Hunt for Domain: {ioc}\n'
                f'data.win.eventdata.queryName:"{ioc}" or url:"{ioc}"'
            )
        elif ioc_type in ('hash', 'md5', 'sha1', 'sha256'):
            return (
                f'// DQL (Wazuh/OpenSearch) - Hunt for Hash: {ioc}\n'
                f'data.win.eventdata.hashes:"{ioc}" or md5:"{ioc}" or sha256:"{ioc}"'
            )
        elif ioc_type == 'url':
            return f'// DQL (Wazuh/OpenSearch) - Hunt for URL: {ioc}\nurl:"{ioc}"'
        return "// DQL - IOC type not supported"

    @staticmethod
    def _generate_suricata_ioc(ioc: str, ioc_type: str, context: Dict) -> str:
        """Generate a Suricata rule for a network IOC."""
        escaped_ioc = str(ioc).replace('\\', '\\\\').replace('"', '\\"').replace(';', '\\;')
        sid = 1_000_000 + int(
            hashlib.sha256(f'{ioc_type}:{ioc}'.encode('utf-8')).hexdigest()[:8], 16
        ) % 8_000_000
        malware_family = context.get('malware_family', 'Unknown') if context else 'Unknown'

        if ioc_type in ('ipv4', 'ip'):
            return (
                f'alert ip $HOME_NET any -> {ioc} any '
                f'(msg:"BTA {malware_family} outbound connection to {escaped_ioc}"; '
                f'sid:{sid}; rev:1;)'
            )
        if ioc_type == 'domain':
            return (
                'alert dns $HOME_NET any -> $EXTERNAL_NET 53 '
                f'(msg:"BTA DNS query for {escaped_ioc}"; dns.query; '
                f'content:"{escaped_ioc}"; nocase; sid:{sid}; rev:1;)'
            )
        if ioc_type == 'url':
            return (
                'alert http $HOME_NET any -> $EXTERNAL_NET any '
                f'(msg:"BTA HTTP request for {escaped_ioc}"; http.uri; '
                f'content:"{escaped_ioc}"; nocase; sid:{sid}; rev:1;)'
            )
        return f'# Suricata rule not supported for IOC type: {ioc_type}'

    @staticmethod
    def _generate_firewall_ioc(ioc: str, ioc_type: str, context: Dict) -> str:
        """Generate a vendor-neutral firewall blocklist entry."""
        if ioc_type not in ('ipv4', 'ip', 'domain', 'url'):
            return f'# Firewall blocklist entry not supported for IOC type: {ioc_type}'

        verdict = context.get('verdict', 'Unknown') if context else 'Unknown'
        if str(verdict).strip().upper() == 'CLEAN':
            return '# No block rule generated: verdict CLEAN. Review before any enforcement.'
        malware_family = context.get('malware_family', 'Unknown') if context else 'Unknown'

        def quote(value: object) -> str:
            return str(value).replace('\\', '\\\\').replace('"', '\\"')

        normalized_type = 'ipv4' if ioc_type == 'ip' else ioc_type
        return (
            f'action=deny indicator_type={normalized_type} indicator="{quote(ioc)}" '
            f'verdict="{quote(verdict)}" malware_family="{quote(malware_family)}"'
        )
    
    @staticmethod
    def _generate_kql_file(file_data: Dict) -> str:
        """Generate KQL rule for file."""
        sha256 = file_data.get('sha256', '')
        filename = file_data.get('filename', '')
        
        return f"""// KQL - Hunt for Malicious File
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 == "{sha256}" or FileName == "{filename}"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName
| summarize count() by DeviceName, FileName, FolderPath"""
    
    @staticmethod
    def _generate_spl_file(file_data: Dict) -> str:
        """Generate SPL rule for file."""
        sha256 = file_data.get('sha256', '')
        filename = file_data.get('filename', '')
        
        return f"""# SPL - Hunt for Malicious File
index=* earliest=-30d
| search (sha256="{sha256}" OR file_name="{filename}")
| stats count by host, file_name, file_path, sha256"""
    
    @staticmethod
    def _generate_yara_file(file_data: Dict) -> str:
        """Generate byte-provable YARA rules for a file."""
        from datetime import datetime

        if file_data.get('emit_yara', True) is False:
            return ''

        filename = file_data.get('filename', 'unknown')
        sha256 = file_data.get('sha256', '')
        md5 = file_data.get('md5', '')
        malware_family = file_data.get('malware_family', 'Unknown')

        # Clean filename for rule name
        rule_name = re.sub(r'[^A-Za-z0-9_]', '_', str(filename))
        rule_name = re.sub(r'_+', '_', rule_name).strip('_') or 'file'
        iocs = file_data.get('iocs', [])

        def meta() -> str:
            return f"""    meta:
        description = "Auto-generated rule for {filename}"
        author = "{BRAND_NAME}"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
        hash_sha256 = "{sha256}"
        hash_md5 = "{md5}"
        malware_family = "{malware_family}"
        severity = "high"
        reference = "https://github.com/ugur-ates/blue-team-assistant\""""

        rules = []
        has_sha256 = isinstance(sha256, str) and re.fullmatch(r'[0-9a-fA-F]{64}', sha256)
        if has_sha256:
            rules.append(
                f"""rule BTA_{rule_name}_exact {{
{meta()}
    condition:
        hash.sha256(0, filesize) == "{sha256}"
}}"""
            )

        if iocs:
            strings = []
            for i, ioc in enumerate(iocs[:5]):
                escaped = str(ioc).replace('\\', '\\\\').replace('"', '\\"')[:50]
                strings.append(f'        $ioc_{i} = "{escaped}" ascii wide nocase')
            rules.append(
                f"""rule BTA_{rule_name}_ioc {{
{meta()}
    strings:
{chr(10).join(strings)}
    condition:
        any of ($ioc_*)
}}"""
            )

        if not rules:
            return ''
        prefix = 'import "hash"\n\n' if has_sha256 else ''
        return prefix + '\n\n'.join(rules) + '\n'
    
    @staticmethod
    def _generate_sigma_file(file_data: Dict) -> str:
        """Generate SIGMA rule for file detection."""
        from datetime import datetime
        
        filename = file_data.get('filename', 'unknown')
        sha256 = file_data.get('sha256', '')
        md5 = file_data.get('md5', '')
        malware_family = file_data.get('malware_family', 'Unknown')
        indicators = file_data.get('suspicious_indicators', [])
        rule_id = uuid.uuid5(uuid.NAMESPACE_URL, f"file:{sha256}")
        
        rule = f"""title: Detection of {malware_family} - {filename}
id: {rule_id}
status: experimental
description: Detects execution or presence of potentially malicious file
author: Ugur Ates
date: {datetime.now().strftime('%Y/%m/%d')}
references:
    - https://github.com/ugur-ates/blue-team-assistant
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1059
    - attack.t1027

logsource:
    category: process_creation
    product: windows

detection:
    selection_hash:
        - Hashes|contains: '{sha256}'
        - Hashes|contains: '{md5}'
    selection_filename:
        - Image|endswith: '\\{filename}'
        - OriginalFileName: '{filename}'"""
        
        if indicators:
            rule += """
    selection_commandline:
        CommandLine|contains:"""
            for ind in indicators[:5]:
                escaped = str(ind)[:50].replace("'", "''")
                rule += f"\n            - '{escaped}'"
        
        rule += """
    
    condition: selection_hash or selection_filename"""
        
        if indicators:
            rule += " or selection_commandline"
        
        rule += f"""

falsepositives:
    - Legitimate administrative tools
    - Software updates

level: high
"""
        
        return rule
    
    @staticmethod
    def generate_email_rules(email_data: Dict) -> Dict[str, str]:
        """
        Generate comprehensive detection rules for phishing email.
        
        Args:
            email_data: Email analysis results
        
        Returns:
            Dict with rules for each platform (KQL, SPL, SIGMA, YARA)
        """
        from datetime import datetime
        
        sender = email_data.get('from', '')
        sender_domain = email_data.get('sender_domain', '')
        if not sender_domain and '@' in sender:
            sender_domain = sender.split('@')[-1].split('>')[0]
        subject = email_data.get('subject', '')[:50]
        urls = email_data.get('urls', [])
        malicious_iocs = email_data.get('malicious_iocs', [])
        
        # KQL Rule
        kql = f"""// KQL - Hunt for Phishing Campaign
// Sender-based detection
EmailEvents
| where Timestamp > ago(30d)
| where SenderFromAddress == "{sender}" 
    or SenderFromDomain == "{sender_domain}"
    or Subject contains "{subject}"
| project Timestamp, RecipientEmailAddress, SenderFromAddress, Subject, NetworkMessageId
| summarize 
    Recipients = make_set(RecipientEmailAddress),
    Count = count() 
    by SenderFromAddress, Subject

// URL-based detection
let malicious_urls = dynamic([{', '.join([f'"{u[:50]}"' for u in urls[:5]])}]);
EmailUrlInfo
| where Timestamp > ago(30d)
| where Url has_any (malicious_urls)
| join kind=inner EmailEvents on NetworkMessageId
| project Timestamp, RecipientEmailAddress, SenderFromAddress, Url
"""

        # SIGMA Rule
        rule_id = uuid.uuid5(uuid.NAMESPACE_URL, f"email:{sender}")
        sigma = f"""title: Phishing Email Detection - {sender_domain}
id: {rule_id}
status: experimental
description: Detects emails from known phishing sender or containing malicious indicators
author: Ugur Ates
date: {datetime.now().strftime('%Y/%m/%d')}
tags:
    - attack.initial_access
    - attack.t1566.001
    - attack.t1566.002
logsource:
    category: email
    product: exchange
    service: messagetrace
detection:
    selection_sender:
        sender|endswith: '@{sender_domain}'
    selection_subject:
        subject|contains: '{subject[:30]}'"""

        if urls:
            sigma += """
    selection_url:
        url|contains:"""
            for u in urls[:3]:
                sigma += f"\n            - '{u[:50]}'"
        
        sigma += """
    condition: selection_sender or selection_subject"""
        if urls:
            sigma += " or selection_url"
        
        sigma += """
falsepositives:
    - Legitimate emails from similar domains
level: high
"""

        # SPL Rule
        spl = f"""# SPL - Hunt for Phishing Email
index=email earliest=-30d
| search sender="{sender}" OR sender_domain="{sender_domain}" OR subject="*{subject[:30]}*"
| stats count by recipient, sender, subject, src_ip
| where count > 1

# URL-based hunt
index=email earliest=-30d
| search url IN ("{('", "'.join(urls[:5]))}")
| stats count by recipient, sender, url
"""

        # YARA for attachments (if any IOCs)
        yara = ""
        if malicious_iocs:
            yara = f"""rule Phishing_Email_IOCs {{
    meta:
        description = "IOCs from phishing email analysis"
        author = "{BRAND_NAME}"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
        sender = "{sender}"
    strings:"""
            for i, ioc in enumerate(malicious_iocs[:10]):
                escaped = str(ioc).replace('\\', '\\\\').replace('"', '\\"')[:50]
                yara += f'\n        $ioc{i} = "{escaped}" ascii wide nocase'
            yara += """
    condition:
        any of them
}"""

        # ==================== EMAIL GATEWAY RULES ====================
        
        # FortiMail Content Filter
        fortimail = f"""# FortiMail Content Filter Rule
# Auto-generated by {BRAND_NAME} - Block phishing campaign

config antispam profile
    edit "BTA-Block-{sender_domain[:20] if sender_domain else 'unknown'}"
        config spam-filtering
            set heuristic enable
        end
        config banned-word
            set status enable
            set entries "{subject[:30]}"
        end
    next
end

# Sender Domain Block
config domain
    edit "{sender_domain}"
        set spam on
        set virus on
        set banned-word on
    next
end

# URL Block Rule (if malicious URLs found)
"""
        if urls:
            fortimail += """config webfilter content
    edit "BTA-Blocked-URLs"
        config entries"""
            for url in urls[:10]:
                url_escaped = url[:60].replace('"', '\\"')
                fortimail += f'\n            edit "{url_escaped}"\n            next'
            fortimail += """
        end
    next
end
"""
        
        # Proofpoint Email Protection Rule
        proofpoint = f"""# Proofpoint Email Protection Rule
# Auto-generated by {BRAND_NAME}

# Sender Block Rule (JSON format for API)
{{
    "rule_name": "BTA-Block-{sender_domain[:20] if sender_domain else 'unknown'}",
    "description": "Block phishing campaign from {sender_domain}",
    "enabled": true,
    "conditions": {{
        "from_header": {{
            "contains": ["{sender_domain}"]
        }},
        "subject": {{
            "contains": ["{subject[:30].replace('"', "'")}"]
        }}
    }},
    "actions": {{
        "quarantine": true,
        "add_header": "X-BTA-Blocked: phishing",
        "notify_admin": true,
        "log_action": true
    }}
}}

# URL Rewrite/Block Rule
{{
    "rule_name": "BTA-URL-Block-{int(hashlib.sha256(sender.encode()).hexdigest()[:8], 16) % 1000:03d}",
    "description": "Block malicious URLs from phishing campaign",
    "enabled": true,
    "conditions": {{
        "url_in_body": {{
            "matches": [
"""
        for url in urls[:5]:
            url_escaped = url[:70].replace('"', '\\"')
            proofpoint += f'                "{url_escaped}",\n'
        proofpoint += """            ]
        }
    },
    "actions": {
        "rewrite_urls": true,
        "block_url_click": true,
        "quarantine": true,
        "sandbox_attachment": true
    }
}
"""
        
        # Mimecast Policy
        mimecast = f"""# Mimecast Content Examination Policy
# Auto-generated by {BRAND_NAME}

Policy Name: BTA-Block-{sender_domain[:15] if sender_domain else 'unknown'}
Policy Type: Content Examination
Status: Enabled
Priority: High

Conditions:
- Header From Contains: {sender_domain}
- Subject Contains: {subject[:30]}
- Attachment Name Pattern: *.exe, *.js, *.vbs, *.ps1, *.hta

Actions:
- Hold Message for Review
- Admin Notification: Enabled
- Add X-Header: X-BTA-Flagged: true
- Send to Sandbox: Enabled

# Blocked Sender Entry
Type: Blocked Sender
Address: *@{sender_domain}
Reason: Phishing campaign detected by {BRAND_NAME}
Duration: Permanent

# URL Protection Policy
URL Categories to Block:
"""
        for url in urls[:5]:
            mimecast += f"- {url[:50]}\n"
        
        # Microsoft 365 Defender / Exchange Online Protection
        microsoft365 = f"""# Microsoft 365 Defender / Exchange Online Protection
# PowerShell commands - Run in Exchange Online PowerShell

# 1. Create Transport Rule to block sender domain
New-TransportRule -Name "BTA-Block-{sender_domain[:20] if sender_domain else 'unknown'}" `
    -FromAddressMatchesPatterns "*@{sender_domain}" `
    -SubjectContainsWords "{subject[:30].replace('"', "'")}" `
    -DeleteMessage $true `
    -SetAuditSeverity "High" `
    -Comments "Auto-generated by {BRAND_NAME} - Phishing campaign block"

# 2. Add sender to blocked senders list
Set-HostedContentFilterPolicy -Identity Default `
    -BlockedSenders @{{Add="{sender}"}} `
    -BlockedSenderDomains @{{Add="{sender_domain}"}}

# 3. Create anti-phishing policy
New-AntiPhishPolicy -Name "BTA-AntiPhish-{int(hashlib.sha256(sender.encode()).hexdigest()[:8], 16) % 1000:03d}" `
    -Enabled $true `
    -EnableOrganizationDomainsProtection $true `
    -EnableMailboxIntelligence $true `
    -EnableMailboxIntelligenceProtection $true `
    -MailboxIntelligenceProtectionAction Quarantine

# 4. Create Safe Links block for malicious URLs
# Note: Requires Microsoft Defender for Office 365 P1/P2
$urls_to_block = @(
"""
        for url in urls[:10]:
            url_escaped = url[:70].replace('"', '`"')
            microsoft365 += f'    "{url_escaped}",\n'
        microsoft365 += """)
# Add to blocked URLs in Defender portal or via API

# 5. Create mail flow rule for URL blocking
New-TransportRule -Name "BTA-Block-URLs" `
    -HeaderContainsMessageHeader "Content-Type" `
    -HeaderContainsWords "text/html" `
    -SubjectOrBodyContainsWords $urls_to_block `
    -Quarantine $true

# 6. Alert rule for SOC
New-ProtectionAlert -Name "BTA-Phishing-Alert" `
    -Category ThreatManagement `
    -NotifyUser "soc@yourdomain.com" `
    -Operation "ThreatIntelligenceUrl"
"""

        return {
            'kql': kql,
            'sigma': sigma,
            'spl': spl,
            'yara': yara,
            'fortimail': fortimail,
            'proofpoint': proofpoint,
            'mimecast': mimecast,
            'microsoft365': microsoft365
        }
