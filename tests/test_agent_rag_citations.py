import json
import logging
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.agent.agent_loop import (
    AgentLoop,
    _build_flow_b_rag_blocks,
    _validate_rag_reference,
)
from src.agent.agent_state import AgentState
from src.rag.rag_knowledge_base import load_playbooks_from_yaml


def _reference(**metadata_overrides):
    metadata = {
        "schema_version": "socpow-rag-provenance/1",
        "citation_id": "mitre_t1566_001",
        "knowledge_type": "attack_pattern",
        "source_name": "MITRE ATT&CK",
        "source_url": "https://attack.mitre.org/techniques/T1566/001/",
        "source_version": "ATT&CK v19.2",
        "confidence": 100,
        "tlp": "TLP:CLEAR",
        "created": "2026-08-09T05:07:48Z",
        "modified": "2026-09-10T17:15:26Z",
        "revoked": False,
    }
    metadata.update(metadata_overrides)
    return {
        "text": "Spearphishing attachments can deliver malware.",
        "metadata": metadata,
        "distance": 0.2,
    }


def _finding(reference):
    return {
        "type": "tool_result",
        "tool": "investigate_ioc",
        "result": {"verdict": "MALICIOUS", "rag_references": [reference]},
    }


def test_all_seed_entries_satisfy_flow_b_provenance_schema():
    documents = load_playbooks_from_yaml()

    assert len(documents) == 9
    for document in documents:
        valid, reason = _validate_rag_reference(document)
        assert valid, f"{document['id']}: {reason}"
        assert document["metadata"]["citation_id"] == document["id"]


def test_valid_provenance_is_rendered_with_stable_citation_id():
    context, sources = _build_flow_b_rag_blocks([_finding(_reference())])

    assert "[KB:mitre_t1566_001]" in context
    assert "Spearphishing attachments" in context
    assert "https://attack.mitre.org/techniques/T1566/001/" in sources


def test_missing_required_provenance_is_excluded(caplog):
    reference = _reference()
    del reference["metadata"]["source_url"]

    with caplog.at_level(logging.WARNING):
        context, sources = _build_flow_b_rag_blocks([_finding(reference)])

    assert context == ""
    assert sources == ""
    assert "invalid provenance" in caplog.text
    assert "source_url" in caplog.text


@pytest.mark.parametrize(
    "metadata_overrides, expected_reason",
    [
        ({"revoked": True}, "revoked"),
        ({"valid_until": "2020-01-01T00:00:00Z"}, "expired"),
    ],
)
def test_inactive_knowledge_is_excluded(
    metadata_overrides,
    expected_reason,
    caplog,
):
    with caplog.at_level(logging.WARNING):
        context, _ = _build_flow_b_rag_blocks(
            [_finding(_reference(**metadata_overrides))]
        )

    assert context == ""
    assert expected_reason in caplog.text


def test_nested_ioc_rag_references_are_found_in_email_tool_result():
    email_finding = {
        "type": "tool_result",
        "tool": "analyze_email",
        "result": {
            "verdict": "PHISHING",
            "ioc_analysis": {
                "results": [
                    {
                        "ioc": "evil.example",
                        "rag_references": [_reference()],
                    }
                ]
            },
        },
    }

    context, _ = _build_flow_b_rag_blocks([email_finding])

    assert "[KB:mitre_t1566_001]" in context


@pytest.mark.asyncio
async def test_think_injects_only_validated_rag_context():
    valid = _reference()
    invalid = _reference(citation_id="invalid_entry")
    del invalid["metadata"]["source_url"]
    invalid["text"] = "UNVALIDATED TEXT MUST NOT LEAK"
    state = AgentState(goal="Investigate phishing")
    state.findings = [_finding(valid), _finding(invalid)]

    loop = object.__new__(AgentLoop)
    loop.tools = MagicMock()
    loop.tools.get_tools_for_llm.return_value = []
    loop.tool_selector = MagicMock()
    loop.tool_selector.build_tools_block.return_value = ""
    loop.tool_selector.build_playbooks_block.return_value = ""
    loop.tool_selector.build_findings_block.side_effect = (
        lambda prompt_state: json.dumps(prompt_state.findings)
    )
    loop.tool_selector.filter_tools_for_goal.return_value = []
    loop._chat_with_tools = AsyncMock(
        return_value={"action": "final_answer", "answer": "done"}
    )

    await loop._think(state)

    messages = loop._chat_with_tools.await_args.args[0]
    prompt = messages[0]["content"]
    assert "Validated RAG context (Flow B only)" in prompt
    assert "[KB:mitre_t1566_001]" in prompt
    assert "UNVALIDATED TEXT MUST NOT LEAK" not in prompt
    assert '"rag_references"' not in prompt


@pytest.mark.asyncio
async def test_final_summary_appends_sources_deterministically():
    state = AgentState(goal="Investigate phishing")
    state.findings = [
        _finding(_reference()),
        {
            "type": "final_answer",
            "answer": "Confirmed phishing activity.",
            "verdict": "MALICIOUS",
        },
    ]
    loop = object.__new__(AgentLoop)

    summary = await loop._generate_summary(state)

    assert summary.startswith("[MALICIOUS] Confirmed phishing activity.")
    assert "Knowledge sources:" in summary
    assert "[KB:mitre_t1566_001]" in summary


def test_rag_confidence_does_not_alter_investigation_verdict():
    import copy

    from src.agent.agent_loop import _strip_rag_references

    stripped_by_rag_confidence = {}
    context_by_rag_confidence = {}

    for rag_confidence in (100, 60):
        findings = [
            {
                "type": "tool_result",
                "tool": "investigate_ioc",
                "result": {
                    "verdict": "SUSPICIOUS",
                    "confidence": 37,
                    "severity": "MEDIUM",
                    "rag_references": [
                        _reference(confidence=rag_confidence)
                    ],
                },
            }
        ]
        findings_before_rag_build = copy.deepcopy(findings)

        context, _ = _build_flow_b_rag_blocks(findings)

        assert findings == findings_before_rag_build

        stripped = _strip_rag_references(findings)
        expected_stripped = copy.deepcopy(findings_before_rag_build)
        del expected_stripped[0]["result"]["rag_references"]

        assert findings == findings_before_rag_build
        assert stripped == expected_stripped
        assert stripped[0]["result"] == {
            "verdict": "SUSPICIOUS",
            "confidence": 37,
            "severity": "MEDIUM",
        }

        stripped_by_rag_confidence[rag_confidence] = stripped
        context_by_rag_confidence[rag_confidence] = context

    assert stripped_by_rag_confidence[100] == stripped_by_rag_confidence[60]
    assert context_by_rag_confidence[100].replace(
        "confidence=100", "confidence=<policy>"
    ) == context_by_rag_confidence[60].replace(
        "confidence=60", "confidence=<policy>"
    )


def test_rag_confidence_field_isolated_to_citation_label_only():
    import ast
    import inspect
    import textwrap

    reference = _reference(confidence=42)
    context, sources = _build_flow_b_rag_blocks([_finding(reference)])
    expected_label = (
        "[KB:mitre_t1566_001] MITRE ATT&CK (ATT&CK v19.2) | "
        "https://attack.mitre.org/techniques/T1566/001/ | "
        "confidence=42 | TLP:CLEAR"
    )

    assert sources == expected_label
    assert context == f"{expected_label}\n{reference['text']}"
    assert context.count("42") == 1
    assert sources.count("42") == 1

    def metadata_confidence_reads(function):
        tree = ast.parse(textwrap.dedent(inspect.getsource(function)))
        return [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and node.value.id == "metadata"
            and isinstance(node.slice, ast.Constant)
            and node.slice.value == "confidence"
        ]

    validation_reads = metadata_confidence_reads(_validate_rag_reference)
    citation_reads = metadata_confidence_reads(_build_flow_b_rag_blocks)

    assert len(validation_reads) == 1
    assert len(citation_reads) == 1

    builder_source = inspect.getsource(_build_flow_b_rag_blocks)
    assert "determine_verdict" not in builder_source
    assert "compute_authoritative_verdict" not in builder_source


@pytest.mark.asyncio
async def test_generate_summary_verdict_unaffected_by_rag_confidence():
    summaries = {}
    loop = object.__new__(AgentLoop)

    for rag_confidence in (100, 60):
        state = AgentState(goal="Investigate phishing")
        state.findings = [
            _finding(_reference(confidence=rag_confidence)),
            {
                "type": "final_answer",
                "answer": "Confirmed phishing activity.",
                "verdict": "MALICIOUS",
            },
        ]

        summaries[rag_confidence] = await loop._generate_summary(state)

    verdict_summary_100, separator_100, sources_100 = summaries[100].partition(
        "\n\nKnowledge sources:\n"
    )
    verdict_summary_60, separator_60, sources_60 = summaries[60].partition(
        "\n\nKnowledge sources:\n"
    )

    assert verdict_summary_100 == verdict_summary_60
    assert verdict_summary_100 == "[MALICIOUS] Confirmed phishing activity."
    assert separator_100 == separator_60 == "\n\nKnowledge sources:\n"
    assert "confidence=100" in sources_100
    assert "confidence=60" in sources_60
    assert sources_100.replace(
        "confidence=100", "confidence=<policy>"
    ) == sources_60.replace("confidence=60", "confidence=<policy>")
