from __future__ import annotations

import re
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from fastapi.templating import Jinja2Templates


ROOT = Path(__file__).resolve().parents[1]


def _render_playbooks() -> str:
    app = FastAPI()
    templates = Jinja2Templates(directory=str(ROOT / "templates"))

    @app.get("/agent/playbooks")
    async def playbooks_page(request: Request):
        request.state.user = {
            "id": 1,
            "username": "playbooks-test",
            "email": "playbooks-test@example.test",
            "role": "admin",
        }
        return templates.TemplateResponse(
            request,
            "playbooks.html",
            {
                "playbooks": [
                    {
                        "id": "alert_triage",
                        "name": "Alert Triage",
                        "category": "Incident Response",
                        "description": "Classify and enrich security alerts.",
                        "trigger_type": "manual",
                        "step_count": 21,
                        "steps": [
                            {"name": "first", "tool": "tool_z"},
                            {"name": "second", "tool": "tool_a"},
                            {"name": "repeat", "tool": "tool_z"},
                            {"name": "finish", "action": "final_answer"},
                        ],
                    }
                ]
            },
        )

    with TestClient(app) as client:
        response = client.get("/agent/playbooks")

    assert response.status_code == 200
    return response.text


def test_playbooks_page_renders_list_header_tiles_meter_and_toolbar() -> None:
    rendered = _render_playbooks()

    assert "/static/css/playbooks.css?v=1" in rendered
    assert '<section class="playbooks-page"' in rendered
    assert re.search(r"<h1>\s*SECURITY\s*<span>PLAYBOOKS</span>\s*</h1>", rendered)
    assert "Pre-configured investigation workflows" in rendered
    assert 'id="refreshPlaybooksBtn"' in rendered
    assert 'onclick="Playbooks.loadPlaybooks()"' in rendered

    stat_labels = re.findall(
        r'<div class="stat-label">([^<]+)</div>',
        rendered.split('id="playbookStatsBar"', 1)[1].split('id="playbookCategoryMeter"', 1)[0],
    )
    assert stat_labels == ["Playbooks", "Total Steps", "Unique Tools", "Categories"]
    assert 'id="statTotalPlaybooks"' in rendered
    assert 'id="statTotalSteps"' in rendered
    assert 'id="statUniqueToolsTile"' in rendered
    assert 'id="statUniqueTools"' in rendered
    assert re.search(r'id="statUniqueTools">2</div>', rendered)
    assert 'id="statCategories"' in rendered
    assert 'id="playbookCategoryMeter" class="playbooks-meter"' in rendered
    assert re.search(r'class="[^"]*playbooks-toolbar[^"]*"', rendered)
    assert '&gt;_' in rendered
    assert 'id="playbookSearchInput"' in rendered
    assert 'placeholder="search playbooks by name or description…"' in rendered
    assert '<kbd class="playbooks-search-hint"' in rendered
    assert 'id="categoryFilters"' in rendered
    assert 'data-category="incident-response"' in rendered
    assert 'id="playbookGrid"' in rendered
    assert 'data-pb-category="incident-response"' in rendered


def test_run_summary_uses_escaped_middot_separators() -> None:
    rendered = _render_playbooks()

    assert r"steps \u00b7 " in rendered
    assert r"trigger \u00b7 Opens in Agent Chat when started" in rendered
    assert "steps ? Manual trigger" not in rendered


def test_playbooks_css_is_scoped_and_uses_square_corners_and_history_title_glow() -> None:
    css = (ROOT / "static" / "css" / "playbooks.css").read_text(encoding="utf-8-sig")

    assert "body:has(.playbooks-page) .sub-header" in css
    assert ".playbooks-page {" in css
    assert re.search(
        r"\.playbooks-page \.playbooks-heading h1\s*\{[^}]*text-shadow:\s*0 0 14px var\(--color-info\)\s*;",
        css,
        re.DOTALL,
    )
    assert "border-radius: 0;" in css
    for page_class in (
        ".playbooks-heading",
        ".playbooks-stats",
        ".playbooks-meter",
        ".playbooks-toolbar",
        ".playbooks-grid",
        ".playbooks-card",
    ):
        assert f".playbooks-page {page_class}" in css


def test_playbooks_cards_have_category_hover_glow_and_reduced_motion_support() -> None:
    css = (ROOT / "static" / "css" / "playbooks.css").read_text(encoding="utf-8-sig")

    hover_rule = re.search(
        r"\.playbooks-page \.playbooks-card:hover,\s*"
        r"\.playbooks-page \.playbooks-card:focus-within,.*?\{([^}]*)\}",
        css,
        re.DOTALL,
    )
    assert hover_rule is not None
    assert "box-shadow:" in hover_rule.group(1)
    assert "var(--playbooks-card-accent" in hover_rule.group(1)
    assert "transform: translateY(-2px);" in hover_rule.group(1)

    assert "@media (prefers-reduced-motion: reduce)" in css
    reduced_motion_css = css.split("@media (prefers-reduced-motion: reduce)", 1)[1].split(
        "@media (hover: none)", 1
    )[0]
    assert "transition: none;" in reduced_motion_css
    assert "transform: none;" in reduced_motion_css


def test_playbooks_stat_tiles_have_scoped_hover_glow() -> None:
    css = (ROOT / "static" / "css" / "playbooks.css").read_text(encoding="utf-8-sig")
    rendered = _render_playbooks()

    # The template keeps the compatibility class, but CSS leaves it visually inert.
    assert "playbooks-stat-highlight" in rendered
    assert ".playbooks-stat-highlight" not in css
    assert "--playbooks-highlight-glow-alpha" not in css

    hover_rule = re.search(
        r"\.playbooks-page \.playbooks-stat:hover,\s*"
        r"\.playbooks-page \.playbooks-stat:focus-within\s*\{([^}]*)\}",
        css,
        re.DOTALL,
    )
    assert hover_rule is not None
    assert "border-color: var(--playbooks-cat-threat-intel);" in hover_rule.group(1)
    assert "box-shadow:" in hover_rule.group(1)
    assert "var(--playbooks-hover-glow-alpha)" in hover_rule.group(1)
    assert "var(--playbooks-hover-glow-size)" in hover_rule.group(1)
    assert re.search(
        r"\.playbooks-page \.playbooks-stat:hover \.stat-value,\s*"
        r"\.playbooks-page \.playbooks-stat:focus-within \.stat-value\s*"
        r"\{[^}]*text-shadow:",
        css,
        re.DOTALL,
    )

    reduced_motion_css = css.split("@media (prefers-reduced-motion: reduce)", 1)[1].split(
        "@media (hover: none)", 1
    )[0]
    assert ".playbooks-page .playbooks-stat" in reduced_motion_css
    assert "transition: none;" in reduced_motion_css


def test_run_modal_footer_uses_two_columns_on_narrow_screens() -> None:
    css = (ROOT / "static" / "css" / "playbooks.css").read_text(encoding="utf-8-sig")
    mobile_match = re.search(r"@media \(max-width: 560px\)\s*\{(.*?)\n\}", css, re.DOTALL)
    assert mobile_match is not None
    mobile_css = mobile_match.group(1)

    assert ".playbooks-run-modal .modal-footer" in mobile_css
    assert "grid-template-columns: repeat(2, minmax(0, 1fr));" in mobile_css
    assert ".playbooks-run-footer-note { grid-column: 1 / -1;" in mobile_css
    assert ".playbooks-run-modal .modal-footer > * { margin: 0; }" in mobile_css
    assert ".playbooks-run-modal .modal-footer > .btn { width: 100%; }" in mobile_css


def test_playbooks_page_keeps_existing_inline_javascript_hooks_and_modals() -> None:
    rendered = _render_playbooks()
    required_ids = (
        "playbookStatsBar",
        "statTotalPlaybooks",
        "statTotalSteps",
        "statUniqueTools",
        "statCategories",
        "playbookSearchInput",
        "categoryFilters",
        "playbookGrid",
        "runPlaybookModal",
        "executePlaybookBtn",
        "viewPlaybookModal",
        "viewModalRunBtn",
    )

    for element_id in required_ids:
        assert f'id="{element_id}"' in rendered

    assert "playbook-view-btn" in rendered
    assert "playbook-run-btn" in rendered
    assert 'data-playbook-id="alert_triage"' in rendered
    assert 'data-playbook-name="Alert Triage"' in rendered
    assert 'class="trigger-badge trigger-manual">manual</span>' in rendered
    assert "21 steps" in rendered
    assert "Array.isArray(pb.tools)" in rendered


def test_playbooks_view_and_run_modals_use_safe_detail_hooks() -> None:
    rendered = _render_playbooks()
    css = (ROOT / "static" / "css" / "playbooks.css").read_text(encoding="utf-8-sig")
    script_start = rendered.index("var Playbooks = (function ()")
    script = rendered[script_start:rendered.index("</script>", script_start)]

    for element_id in (
        "runPlaybookModal",
        "runPlaybookForm",
        "runPlaybookId",
        "runParamFieldsContainer",
        "runParamsFallback",
        "playbookParams",
        "runInputModeSwitch",
        "runFormModeBtn",
        "runRawModeBtn",
        "runPlaybookSummary",
        "runPlaybookError",
        "executePlaybookBtn",
        "viewPlaybookModal",
        "viewPlaybookBody",
        "viewModalRunBtn",
    ):
        assert f'id="{element_id}"' in rendered

    assert "Required fields are checked before the run starts" in rendered
    assert "Suspicious login from 10.0.0.1" not in rendered
    assert "data.tool_display" in script
    assert "buildToolCoverage" in script
    assert "chip.setAttribute('title', tool.id)" in script
    for selector in (
        ".playbooks-run-field",
        ".playbooks-run-tag",
        ".playbooks-run-error",
        ".playbooks-view-tool-group",
        ".playbooks-view-tool-chip",
        ".playbooks-view-more-groups",
    ):
        assert selector in css

    run_js = script[
        script.index("    function openRunModal("):
        script.index("    function displayPlaybookTool(")
    ]
    view_js = script[
        script.index("    function displayPlaybookTool("):
        script.index("    /*", script.index("    function viewPlaybook("))
    ]
    assert ".innerHTML" not in run_js
    assert ".innerHTML" not in view_js
    assert "JSON.stringify({ params: params })" in run_js


def test_guided_playbook_modals_share_storage_backed_toggle_and_safe_form_rendering() -> None:
    rendered = _render_playbooks()
    script_start = rendered.index("var Playbooks = (function ()")
    script = rendered[script_start:rendered.index("</script>", script_start)]
    run_form_js = script[
        script.index("    function renderRunFields("):
        script.index("    function openRunModal(")
    ]
    open_run_js = script[
        script.index("    function openRunModal("):
        script.index("    document.getElementById('runFormModeBtn')")
    ]

    assert rendered.count('<input type="checkbox" data-guide-toggle>') == 2
    assert rendered.count('class="playbooks-guide-toggle"') == 2
    assert "socpow.playbooks.guide" in script
    assert "window.localStorage.getItem(GUIDE_STORAGE_KEY)" in script
    assert "window.localStorage.setItem(GUIDE_STORAGE_KEY" in script
    assert re.search(r"function readGuidePreference\(\)\s*\{\s*try\s*\{", script)
    assert re.search(r"function setGuideEnabled\(enabled\)\s*\{\s*guideEnabled = enabled;\s*try\s*\{", script)
    assert "required ? 'REQUIRED' : 'OPTIONAL'" in run_form_js
    assert "definition.required === true" in run_form_js
    assert "definition.example" in run_form_js
    assert "input.placeholder" not in run_form_js
    assert "Fill with example" in run_form_js
    assert "var params = Array.isArray(data.input_params) ? data.input_params : [];" in open_run_js
    assert re.search(r"if \(params\.length\)\s*\{.*?setRunMode\('form'\);\s*\} else \{.*?setRunMode\('raw'\);", open_run_js, re.DOTALL)
    assert "definition.default" not in run_form_js
    assert ".default" not in run_form_js
    assert ".innerHTML" not in run_form_js


def test_description_clamp_and_toggle_are_limited_to_guide_mode() -> None:
    rendered = _render_playbooks()
    css = (ROOT / "static" / "css" / "playbooks.css").read_text(encoding="utf-8-sig")
    script_start = rendered.index("var Playbooks = (function ()")
    script = rendered[script_start:rendered.index("</script>", script_start)]

    assert 'id="runPlaybookDescToggle"' in rendered
    assert 'aria-expanded="false" aria-controls="runPlaybookDesc"' in rendered
    assert "Show full description" in script
    assert "Show less" in script
    assert "toggle.setAttribute('aria-expanded', expanded ? 'true' : 'false')" in script
    assert "description.classList.toggle('playbooks-description-clamped', guideEnabled && !expanded)" in script
    assert "description.classList.toggle('playbooks-description-expanded', guideEnabled && expanded)" in script
    assert "description.scrollHeight > description.clientHeight" in script
    assert "shown.bs.modal" in script
    assert "description.textContent = data.description || ''" in script

    assert re.search(
        r"\.playbooks-description-clamped\s*\{[^}]*-webkit-line-clamp:\s*2\s*;",
        css,
        re.DOTALL,
    )
    assert re.search(
        r"\.playbooks-description-expanded\s*\{[^}]*white-space:\s*pre-line\s*;",
        css,
        re.DOTALL,
    )
    assert re.search(r"\.playbooks-description-toggle\[hidden\]\s*\{[^}]*display:\s*none\s*!important", css)


def test_view_description_order_changes_only_in_guide_mode_and_resets_on_open() -> None:
    rendered = _render_playbooks()
    script_start = rendered.index("var Playbooks = (function ()")
    script = rendered[script_start:rendered.index("</script>", script_start)]
    render_view = script[
        script.index("    function renderViewDetails("):
        script.index("    function viewPlaybook(")
    ]
    view_open = script[
        script.index("    function viewPlaybook("):
        script.index("    /*", script.index("    function viewPlaybook("))
    ]
    run_open = script[
        script.index("    function openRunModal("):
        script.index("    document.getElementById('runFormModeBtn')")
    ]

    guide_order = [
        render_view.index("body.appendChild(badges)"),
        render_view.index("body.appendChild(what)"),
        render_view.index("body.appendChild(provide)"),
        render_view.index("if (guideEnabled && description.textContent)"),
        render_view.index("body.appendChild(description)", render_view.index("if (guideEnabled && description.textContent)")),
    ]
    assert guide_order == sorted(guide_order)

    non_guide_description = render_view.index(
        "if (!guideEnabled && description.textContent) body.appendChild(description)"
    )
    assert non_guide_description < render_view.index("body.appendChild(badges)")
    assert "viewDescriptionExpanded = false;" in view_open
    assert "runDescriptionExpanded = false;" in run_open
    assert "viewPlaybookModal').addEventListener('shown.bs.modal'" in script
    assert "runPlaybookModal').addEventListener('shown.bs.modal'" in script
