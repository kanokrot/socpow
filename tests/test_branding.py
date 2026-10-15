import re
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.branding import BRAND_NAME, BRAND_TAGLINE
from src.integrations.stix_generator import STIXGenerator
from src.reporting import (
    executive_pdf,
    html_generator,
    incident_report_pdf,
    ioc_pdf,
    markdown_generator,
)
from src.web import page_auth
from src.web.analysis_manager import AnalysisManager
from src.web.app import _register_page_routes, create_app
from src.web.page_auth import PageAuthMiddleware


def test_shared_templates_expose_brand_globals():
    app = create_app()
    templates = app.state.templates

    assert templates.env.globals["BRAND_NAME"] == BRAND_NAME
    assert templates.env.globals["BRAND_TAGLINE"] == BRAND_TAGLINE

    rendered = templates.env.from_string(
        "{{ BRAND_NAME }} - {{ BRAND_TAGLINE }}"
    ).render()
    assert rendered == "SOCPOW - Every IOC gets the POW"


def test_fallback_templates_expose_brand_globals():
    app = FastAPI()
    _register_page_routes(app)

    assert app.state.templates.env.globals["BRAND_NAME"] == BRAND_NAME
    assert app.state.templates.env.globals["BRAND_TAGLINE"] == BRAND_TAGLINE


def test_login_page_displays_brand_and_tagline():
    response = TestClient(create_app()).get("/login")

    assert response.status_code == 200
    title = re.search(r"<title>(.*?)</title>", response.text, re.DOTALL)
    assert title is not None
    assert BRAND_NAME in title.group(1)
    assert "CABTA" not in title.group(1)
    wordmark = re.search(r'<span class="brand-wordmark">(.*?)</span>', response.text, re.DOTALL)
    assert wordmark is not None
    assert f"<strong>{BRAND_NAME}</strong>" in wordmark.group(1)
    assert f"<small>{BRAND_TAGLINE}</small>" in wordmark.group(1)
    assert '<img src="/static/img/logo.svg"' not in response.text
    assert "Cyan Agent Blue Team Assistant" not in response.text


def test_no_old_brand_in_templates():
    templates_dir = Path(__file__).parents[1] / "templates"
    jinja_comment = re.compile(r"{#.*?#}", re.DOTALL)

    for template_path in templates_dir.glob("*.html"):
        content = jinja_comment.sub("", template_path.read_text(encoding="utf-8"))
        assert "Blue Team Assistant" not in content, template_path.name
        assert "Cyan Agent" not in content, template_path.name


def test_agent_chat_page_uses_branded_agent_name(monkeypatch, tmp_path):
    user = {
        "id": 1,
        "email": "hunter@example.test",
        "username": "hunter",
        "role": "Threat Hunter",
        "is_active": 1,
    }
    monkeypatch.setattr(page_auth, "get_current_user", lambda token, request=None: user)

    app = FastAPI()
    app.add_middleware(PageAuthMiddleware)
    app.state.analysis_manager = AnalysisManager(db_path=str(tmp_path / "analysis.db"))
    _register_page_routes(app)

    with TestClient(app) as client:
        client.cookies.set("cabta_session", "test-token")
        response = client.get("/")

    assert response.status_code == 200
    assert f'<span class="brand-wordmark"><strong>{BRAND_NAME}</strong><small>{BRAND_TAGLINE}</small></span>' in response.text
    assert 'class="brand-logo"' not in response.text
    assert f'<strong class="brand-wordmark-glow">{BRAND_NAME}</strong> Agent' in response.text
    assert "agent-empty-state-logo" not in response.text
    assert "Cyan Agent" not in response.text
    title = re.search(r"<title>(.*?)</title>", response.text, re.DOTALL)
    assert title is not None
    assert "Blue Team Assistant" not in title.group(1)


def _flowable_text(flowables):
    for flowable in flowables:
        text = getattr(flowable, "text", None)
        if isinstance(text, str):
            yield text
        for row in getattr(flowable, "_cellvalues", ()):
            yield from _flowable_text(row)
        if isinstance(flowable, (list, tuple)):
            yield from _flowable_text(flowable)


def test_pdf_generators_use_central_brand_in_builder_inputs(monkeypatch, tmp_path):
    captured_ioc_story = []
    captured_incident_story = []

    class CapturingDocument:
        def __init__(self, captured, *args, **kwargs):
            self.captured = captured

        def build(self, story):
            self.captured.extend(story)

    monkeypatch.setattr(
        ioc_pdf,
        "SimpleDocTemplate",
        lambda *args, **kwargs: CapturingDocument(captured_ioc_story),
    )
    monkeypatch.setattr(
        incident_report_pdf,
        "SimpleDocTemplate",
        lambda *args, **kwargs: CapturingDocument(captured_incident_story),
    )

    ioc_result = ioc_pdf.generate_ioc_pdf(
        {"summary": "summary"},
        str(tmp_path / "ioc.pdf"),
        {"analysis_type": "file", "version": "2.0.0"},
    )
    incident_result = incident_report_pdf.generate_incident_report_pdf(
        {}, str(tmp_path / "incident.pdf")
    )

    assert ioc_result is not None
    assert incident_result is not None
    ioc_text = " ".join(_flowable_text(captured_ioc_story))
    incident_text = " ".join(_flowable_text(captured_incident_story))
    assert BRAND_NAME in ioc_text
    assert "SOCPOW v2.0.0" in ioc_text
    assert BRAND_NAME in incident_text
    assert "Cyan Agent Blue Team Assistant" not in ioc_text
    assert "Cyan Agent Blue Team Assistant" not in incident_text


def test_executive_markdown_and_html_reports_use_central_brand(monkeypatch, tmp_path):
    captured_story = []

    class CapturingDocument:
        def __init__(self, *args, **kwargs):
            pass

        def build(self, story):
            captured_story.extend(story)

    monkeypatch.setattr(
        executive_pdf,
        "SimpleDocTemplate",
        lambda *args, **kwargs: CapturingDocument(),
    )
    pdf_result = executive_pdf.generate_executive_pdf(
        {}, str(tmp_path / "executive.pdf")
    )
    pdf_text = " ".join(_flowable_text(captured_story))
    markdown_text = markdown_generator.MarkdownReportGenerator.generate_ioc_report({})
    html_text = html_generator.HTMLReportGenerator.generate_ioc_report({})

    assert pdf_result is not None
    for output in (pdf_text, markdown_text, html_text):
        assert BRAND_NAME in output
        assert "Blue Team Assistant" not in output


def test_stix_identity_uses_brand_name_without_deriving_id_from_name():
    identity = STIXGenerator().create_identity()

    assert identity["name"] == BRAND_NAME
    assert identity["description"] == f"{BRAND_NAME} - {BRAND_TAGLINE}"
    assert "Cyber Blue Team Assistant" not in identity["description"]
    assert identity["id"].startswith("identity--")
