from unittest.mock import AsyncMock, MagicMock, mock_open
from email.message import EmailMessage

import pytest

from src.integrations.llm_analyzer import LLMAnalyzer
from src.tools.email_analyzer import EmailAnalyzer
import src.tools.email_analyzer as email_analyzer_module


RAG_HIT = {
    'text': 'Follow the phishing-email containment playbook.',
    'metadata': {'category': 'playbook', 'verdict': 'PHISHING', 'ioc_type': 'email'},
    'distance': 0.1,
}


@pytest.fixture
def email_pipeline(monkeypatch):
    analyzer = EmailAnalyzer.__new__(EmailAnalyzer)
    analyzer.config = {'analysis': {'enable_llm': True}}
    analyzer.llm_analyzer = LLMAnalyzer({'llm': {'provider': 'ollama'}})
    analyzer.llm_analyzer._call_ollama_api = AsyncMock(
        return_value={
            'verdict': 'CLEAN',
            'analysis': 'Email analysis completed.',
            'recommendations': [],
        }
    )
    analyzer.advanced_analyzer = MagicMock()
    analyzer.advanced_analyzer.analyze_headers.return_value = {
        'anomalies': [],
        'received_chain': [],
        'x_headers': {},
    }
    analyzer.advanced_analyzer.detect_link_text_mismatch.return_value = []
    analyzer.advanced_analyzer.detect_lookalike_domains.return_value = []
    analyzer.advanced_analyzer.analyze_html_obfuscation.return_value = {
        'risk_score': 0,
    }
    analyzer.advanced_analyzer.detect_qr_codes.return_value = {
        'qr_codes_found': 0,
    }
    analyzer.advanced_analyzer.detect_brand_impersonation.return_value = []
    analyzer.advanced_analyzer.fingerprint_email_template.return_value = {}
    analyzer.bec_detector = MagicMock()
    analyzer.bec_detector.analyze.return_value = {
        'bec_score': 0,
        'verdict': 'LOW',
        'indicator_count': 0,
        'has_financial_indicators': False,
        'has_impersonation_indicators': False,
    }
    analyzer.ioc_investigator = None
    analyzer.file_analyzer = None
    analyzer.rag_kb = MagicMock()
    analyzer._extract_email_data = AsyncMock(
        return_value={
            'from': 'sender@example.com',
            'to': 'recipient@example.com',
            'subject': 'Quarterly update',
            'date': '',
            'reply_to': '',
            'body_text': 'Routine message.',
            'body_html': '',
            'attachments': [],
            'urls': [],
            'ips': [],
            'domains': [],
        }
    )

    monkeypatch.setattr(
        email_analyzer_module.EmailForensics,
        'perform_full_forensics',
        MagicMock(return_value={'forensics_score': 0}),
    )
    monkeypatch.setattr(
        email_analyzer_module.EmailThreatIndicators,
        'run_all_checks',
        MagicMock(
            return_value={
                'checks_run': 10,
                'overall_severity': 'NONE',
                'total_score_impact': 0,
                'active_checks': [],
            }
        ),
    )
    monkeypatch.setattr(
        email_analyzer_module.RuleGenerator,
        'generate_email_rules',
        MagicMock(return_value={}),
    )

    message = EmailMessage()
    message['From'] = 'sender@example.com'
    message['To'] = 'recipient@example.com'
    message['Subject'] = 'Quarterly update'
    message.set_content('Routine message.')
    monkeypatch.setattr('builtins.open', mock_open(read_data=b''))
    monkeypatch.setattr(
        email_analyzer_module.email,
        'message_from_binary_file',
        MagicMock(return_value=message),
    )
    return analyzer, 'message.eml'


@pytest.mark.asyncio
async def test_email_prompt_characterization_has_no_rag_section():
    analyzer = LLMAnalyzer({'llm': {'provider': 'ollama'}})
    analyzer._call_ollama_api = AsyncMock(
        return_value={'verdict': 'CLEAN', 'analysis': 'No threat found.'}
    )

    result = await analyzer.analyze_email({})

    assert result['verdict'] == 'CLEAN'
    prompt = analyzer._call_ollama_api.await_args.args[0]
    assert 'Relevant Knowledge Base Entries' not in prompt


@pytest.mark.asyncio
async def test_email_prompt_includes_rag_hit_from_successful_query(email_pipeline):
    analyzer, email_path = email_pipeline
    analyzer.rag_kb.query.return_value = [RAG_HIT]

    result = await analyzer.analyze(str(email_path))

    assert result['verdict'] == 'CLEAN'
    analyzer.rag_kb.query.assert_called_once()
    query_args, query_kwargs = analyzer.rag_kb.query.call_args
    assert query_args[0].startswith('phishing email CLEAN threat score ')
    assert query_kwargs == {
        'category_filter': 'playbook',
        'max_distance': 0.60,
    }
    prompt = analyzer.llm_analyzer._call_ollama_api.await_args.args[0]
    assert '**Relevant Knowledge Base Entries:**' in prompt
    assert RAG_HIT['text'] in prompt


@pytest.mark.asyncio
async def test_email_result_exposes_rag_references_from_successful_query(email_pipeline):
    analyzer, email_path = email_pipeline
    rag_context = [RAG_HIT]
    analyzer.rag_kb.query.return_value = rag_context

    result = await analyzer.analyze(str(email_path))

    assert result['rag_references'] == rag_context


@pytest.mark.asyncio
async def test_email_analysis_continues_when_rag_query_fails(email_pipeline):
    analyzer, email_path = email_pipeline
    analyzer.rag_kb.query.side_effect = RuntimeError('RAG unavailable')

    result = await analyzer.analyze(str(email_path))

    assert 'error' not in result
    assert result['verdict'] == 'CLEAN'
    prompt = analyzer.llm_analyzer._call_ollama_api.await_args.args[0]
    assert 'Relevant Knowledge Base Entries' not in prompt


@pytest.mark.asyncio
async def test_email_result_has_empty_rag_references_when_query_fails(email_pipeline):
    analyzer, email_path = email_pipeline
    analyzer.rag_kb.query.side_effect = RuntimeError('RAG unavailable')

    result = await analyzer.analyze(str(email_path))

    assert result['rag_references'] == []


@pytest.mark.asyncio
async def test_email_result_has_empty_rag_references_when_llm_disabled(email_pipeline):
    analyzer, email_path = email_pipeline
    analyzer.config = {'analysis': {'enable_llm': False}}

    result = await analyzer.analyze(str(email_path))

    assert result['rag_references'] == []
    analyzer.rag_kb.query.assert_not_called()
    analyzer.llm_analyzer._call_ollama_api.assert_not_awaited()


def test_flow_b_finds_email_level_rag_references_without_nested_iocs():
    from src.agent.agent_loop import _build_flow_b_rag_blocks

    reference = {
        'text': 'Follow the phishing-email containment playbook.',
        'metadata': {
            'schema_version': 'socpow-rag-provenance/1',
            'citation_id': 'email_phishing_playbook',
            'knowledge_type': 'course_of_action',
            'source_name': 'Email Phishing Playbook',
            'source_url': 'https://example.com/playbooks/email-phishing',
            'source_version': '1.0',
            'confidence': 90,
            'tlp': 'TLP:CLEAR',
            'created': '2026-09-01T00:00:00Z',
            'modified': '2026-09-01T00:00:00Z',
            'revoked': False,
        },
        'distance': 0.1,
    }
    email_finding = {
        'type': 'tool_result',
        'tool': 'analyze_email',
        'result': {
            'verdict': 'PHISHING',
            'rag_references': [reference],
            'ioc_analysis': {'results': []},
        },
    }

    context, sources = _build_flow_b_rag_blocks([email_finding])

    assert '[KB:email_phishing_playbook]' in context
    assert reference['text'] in context
    assert '[KB:email_phishing_playbook]' in sources


def test_email_analyzer_rag_init_failure_is_nonfatal(monkeypatch):
    monkeypatch.setattr(
        email_analyzer_module,
        'RAGKnowledgeBase',
        MagicMock(side_effect=RuntimeError('RAG unavailable')),
    )

    analyzer = EmailAnalyzer({'analysis': {'enable_rag': True}})

    assert analyzer.rag_kb is None
