"""Structured playbook parameter parsing through the chat route."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web.auth import get_current_user
from src.web.routes.chat import router as chat_router


def _post_playbook_message(message):
    engine = SimpleNamespace(start=AsyncMock(return_value="session-test"))
    app = FastAPI()
    app.state.agent_loop = MagicMock()
    app.state.playbook_engine = engine
    app.dependency_overrides[get_current_user] = lambda: {
        "id": 1,
        "email": "responder@example.test",
        "role": "Incident Responder",
    }
    app.include_router(chat_router, prefix="/api/chat")

    response = TestClient(app).post(
        "/api/chat",
        json={
            "message": message,
            "playbook_id": "forensic_triage",
        },
    )

    assert response.status_code == 200
    engine.start.assert_awaited_once()
    return engine.start.await_args.args[1]


def test_chat_parses_complete_multiline_structured_params():
    remote_key_path = (
        r"D:\ai_cti_automate\test_keys\socpow_test_key"
    )
    message = "\n".join([
        "host_identifier: 192.168.73.5",
        "remote_username: kali",
        f"remote_key_path: {remote_key_path}",
    ])

    input_data = _post_playbook_message(message)

    assert input_data == {
        "query": message,
        "user_input": message,
        "host_identifier": "192.168.73.5",
        "remote_username": "kali",
        "remote_key_path": remote_key_path,
    }


def test_chat_plain_text_preserves_original_input_data():
    message = "192.168.73.5"

    input_data = _post_playbook_message(message)

    assert input_data == {
        "query": message,
        "user_input": message,
    }


def test_chat_mixed_structured_and_plain_lines_falls_back_completely():
    message = "\n".join([
        "host_identifier: 192.168.73.5",
        "plain text without colon",
        "remote_username: kali",
    ])

    input_data = _post_playbook_message(message)

    assert input_data == {
        "query": message,
        "user_input": message,
    }
    assert "host_identifier" not in input_data
    assert "remote_username" not in input_data


def test_chat_preserves_typo_in_structured_param_key():
    message = "\n".join([
        "host_identifer: 192.168.73.5",
        "remote_username: kali",
        r"remote_key_path: D:\keys\socpow_test_key",
    ])

    input_data = _post_playbook_message(message)

    assert input_data["host_identifer"] == "192.168.73.5"
    assert "host_identifier" not in input_data
    assert input_data["remote_username"] == "kali"
    assert input_data["remote_key_path"] == (
        r"D:\keys\socpow_test_key"
    )
    assert input_data["query"] == message
    assert input_data["user_input"] == message
