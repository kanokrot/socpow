"""
Author: Ugur Ates
FastAPI Application Factory - Blue Team Assistant Web Dashboard.

Usage::

    uvicorn src.web.app:create_app --factory --host 0.0.0.0 --port 8080
"""

from dotenv import load_dotenv

load_dotenv()

import asyncio
from copy import copy
from io import BytesIO
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote
from zipfile import ZIP_DEFLATED, ZipFile

from fastapi import Depends, FastAPI, Form, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import RedirectResponse, Response

from src.branding import BRAND_NAME

from .routes import analysis, dashboard, reports, config_api, cases, tickets
from .routes import agent as agent_routes
from .routes import auth as auth_routes
from .routes import admin as admin_routes
from .routes import chat as chat_routes
from .routes import playbooks as playbook_routes
from .routes import mcp_management as mcp_routes
from .routes import access_requests as access_request_routes
from .routes import gmail_settings as gmail_routes
from .routes import account_api_keys as account_api_keys_routes
from .routes import helpdesk as helpdesk_routes
from . import websocket
from .auth import TEAM_LEAD, get_current_user, get_user_ids_by_role, require_role
from .analysis_manager import AnalysisManager
from .case_store import CaseStore
from .page_auth import (
    PageAuthMiddleware,
    ROLE_DEFAULT_LANDING,
    page_auth_user as _page_auth_user,
)
from .security import safe_relative_path
from src.integrations.ticketing import initialize_database as initialize_ticketing_db
from src.branding import BRAND_NAME, BRAND_TAGLINE

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).parent.parent.parent
CONFIG_FILE = Path(os.environ.get('BTA_CONFIG') or PROJECT_ROOT / 'config.yaml')


def _load_config() -> dict:
    """Load configuration from config.yaml (or return sensible defaults)."""
    try:
        import yaml
        if CONFIG_FILE.is_file():
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                cfg = yaml.safe_load(f) or {}
            logger.info("[WEB] Configuration loaded from %s", CONFIG_FILE)
            return cfg
    except ImportError:
        logger.debug("[WEB] PyYAML not installed -- using default config")
    except Exception as exc:
        logger.warning("[WEB] Failed to load config.yaml: %s", exc)

    return {
        'llm': {
            'provider': 'ollama',
            'ollama_endpoint': 'http://localhost:11434',
            'ollama_model': 'llama3.1:8b',
        },
        'agent': {'max_steps': 50},
        'api_keys': {},
    }


TEMPLATES_DIR = PROJECT_ROOT / 'templates'
STATIC_DIR = PROJECT_ROOT / 'static'


def _register_brand_globals(templates: Jinja2Templates) -> None:
    templates.env.globals.update(
        BRAND_NAME=BRAND_NAME,
        BRAND_TAGLINE=BRAND_TAGLINE,
    )


def _page_auth_redirect(request: Request):
    if _page_auth_user(request) is not None:
        return None
    next_path = safe_relative_path(request.url.path)
    return RedirectResponse(
        url=f"/login?next={quote(next_path, safe='')}",
        status_code=303,
    )


class NoCacheStaticMiddleware(BaseHTTPMiddleware):
    """Prevent browser caching of static JS/CSS during development."""

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        if request.url.path.startswith('/static/'):
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
        return response


@asynccontextmanager
async def _lifespan(app: FastAPI):
    """Application lifespan: auto-connect MCP servers on startup."""
    from src.utils.dga_detector import _DICTIONARY_WORDS

    logger.info("[STARTUP] DGA dictionary loaded: %d words", len(_DICTIONARY_WORDS))
    await _auto_connect_mcp_servers(app)

    # Capture the loop MCP stdio connections actually live on so
    # AgentLoop.run_tool() can bridge into it via run_coroutine_threadsafe
    # when invoked from a background thread (investigate()/playbook runs).
    # Without this, playbook-only runs that never call investigate() first
    # leave AgentLoop._main_loop as None and every MCP call stalls until
    # the internal 60s timeout in MCPClientManager.call_tool() fires.
    agent_loop = getattr(app.state, 'agent_loop', None)
    if agent_loop is not None:
        agent_loop._main_loop = asyncio.get_running_loop()
        logger.info("[WEB] Captured main event loop for AgentLoop MCP bridging")

    digest_task = None
    notification_manager = getattr(app.state, "notification_manager", None)
    if notification_manager is not None and notification_manager.enabled:
        from src.integrations.notification_digest import run_digest_loop

        digest_task = asyncio.create_task(run_digest_loop(notification_manager))
        app.state.notification_digest_task = digest_task

    threat_feed_task = None
    from src.integrations.threat_feed_sync import run_sync_loop, sync_enabled
    if sync_enabled():
        threat_feed_task = asyncio.create_task(run_sync_loop(app))
        app.state.threat_feed_sync_task = threat_feed_task

    yield
    if threat_feed_task is not None:
        threat_feed_task.cancel()
        try:
            await threat_feed_task
        except asyncio.CancelledError:
            pass
    if digest_task is not None:
        digest_task.cancel()
        try:
            await digest_task
        except asyncio.CancelledError:
            pass
    # Cleanup: disconnect MCP servers on shutdown
    mcp_client = getattr(app.state, 'mcp_client', None)
    if mcp_client:
        try:
            await mcp_client.disconnect_all()
            logger.info("[WEB] Disconnected all MCP servers during shutdown")
        except Exception as exc:
            logger.warning("[WEB] Error disconnecting MCP servers on shutdown: %s", exc)


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""

    app = FastAPI(
        title=BRAND_NAME,
        description='SOC Analysis Toolkit - Web Dashboard',
        version='2.0.0',
        docs_url='/api/docs',
        redoc_url='/api/redoc',
        lifespan=_lifespan,
    )

    # Protect browser pages and documentation with a valid session.
    app.add_middleware(PageAuthMiddleware)

    # Prevent static file caching
    app.add_middleware(NoCacheStaticMiddleware)

    # Static files
    if STATIC_DIR.exists():
        app.mount('/static', StaticFiles(directory=str(STATIC_DIR)), name='static')

    # Shared state
    app.state.analysis_manager = AnalysisManager()
    app.state.case_store = CaseStore()
    app.state.templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    _register_brand_globals(app.state.templates)

    # Agent components (lazy-initialized; set to None so routes can check availability)
    app.state.agent_store = None
    app.state.agent_loop = None
    app.state.mcp_client = None
    app.state.playbook_engine = None
    app.state.tool_registry = None

    # Load configuration
    config = _load_config()
    app.state.config = config

    # Initialize Ticketing Database
    try:
        initialize_ticketing_db()
    except Exception as e:
        logger.critical(f"[WEB] Failed to initialize ticketing database: {e}")

    try:
        from src.agent.agent_store import AgentStore
        app.state.agent_store = AgentStore()
        logger.info("[WEB] AgentStore initialized")
    except Exception as exc:
        logger.warning(f"[WEB] AgentStore not available: {exc}")

    # Tool instances (used by ToolRegistry)
    app.state.ioc_investigator = None
    app.state.malware_analyzer = None
    app.state.email_analyzer = None
    app.state.correlation_engine = None
    app.state.investigation_memory = None
    app.state.sandbox_orchestrator = None

    try:
        from src.agent.tool_registry import ToolRegistry
        app.state.tool_registry = ToolRegistry()

        # Instantiate real tool classes
        ioc_inv = None
        mal_ana = None
        email_ana = None

        try:
            from src.tools.ioc_investigator import IOCInvestigator
            ioc_inv = IOCInvestigator(config)
            app.state.ioc_investigator = ioc_inv
            logger.info("[WEB] IOCInvestigator initialized")
        except Exception as e:
            logger.warning(f"[WEB] IOCInvestigator not available: {e}")

        try:
            from src.tools.malware_analyzer import MalwareAnalyzer
            mal_ana = MalwareAnalyzer(config)
            app.state.malware_analyzer = mal_ana
            logger.info("[WEB] MalwareAnalyzer initialized")
        except Exception as e:
            logger.warning(f"[WEB] MalwareAnalyzer not available: {e}")

        try:
            from src.tools.email_analyzer import EmailAnalyzer
            email_ana = EmailAnalyzer(config)
            app.state.email_analyzer = email_ana
            logger.info("[WEB] EmailAnalyzer initialized")
        except Exception as e:
            logger.warning(f"[WEB] EmailAnalyzer not available: {e}")

        # Wire cross-tool references
        if mal_ana and ioc_inv:
            mal_ana.ioc_investigator = ioc_inv

        # Register all tools (with full instances where available)
        try:
            app.state.tool_registry.register_default_tools(
                config,
                ioc_investigator=ioc_inv,
                malware_analyzer=mal_ana,
                email_analyzer=email_ana,
            )
        except Exception as reg_exc:
            logger.warning(f"[WEB] Default tool registration partial: {reg_exc}")

        logger.info("[WEB] ToolRegistry initialized with %d tools", len(app.state.tool_registry.list_tools()))
    except Exception as exc:
        logger.warning(f"[WEB] ToolRegistry not available: {exc}")

    # Correlation Engine
    try:
        from src.agent.correlation import CorrelationEngine
        app.state.correlation_engine = CorrelationEngine()
        logger.info("[WEB] CorrelationEngine initialized")
    except Exception as exc:
        logger.warning(f"[WEB] CorrelationEngine not available: {exc}")

    # Investigation Memory
    try:
        from src.agent.memory import InvestigationMemory
        app.state.investigation_memory = InvestigationMemory()
        logger.info("[WEB] InvestigationMemory initialized")
    except Exception as exc:
        logger.warning(f"[WEB] InvestigationMemory not available: {exc}")

    # Sandbox Orchestrator
    try:
        from src.agent.sandbox_orchestrator import SandboxOrchestrator
        app.state.sandbox_orchestrator = SandboxOrchestrator(config)
        logger.info("[WEB] SandboxOrchestrator initialized")
    except Exception as exc:
        logger.warning(f"[WEB] SandboxOrchestrator not available: {exc}")

    # MCP Client Manager
    try:
        from src.agent.mcp_client import MCPClientManager
        app.state.mcp_client = MCPClientManager(agent_store=app.state.agent_store)
        logger.info("[WEB] MCPClientManager initialized")
    except Exception as exc:
        logger.warning(f"[WEB] MCPClientManager not available: {exc}")

    # LLM Analyzer
    app.state.llm_analyzer = None
    try:
        from src.integrations.llm_analyzer import LLMAnalyzer
        app.state.llm_analyzer = LLMAnalyzer(config)
        logger.info("[WEB] LLMAnalyzer initialized")
    except Exception as exc:
        logger.warning(f"[WEB] LLMAnalyzer not available: {exc}")

    # Notification Manager
    app.state.notification_manager = None
    try:
        from src.integrations.notifications import NotificationManager
        app.state.notification_manager = NotificationManager(config)
        logger.info("[WEB] NotificationManager initialized")
    except Exception as exc:
        logger.warning(f"[WEB] NotificationManager not available: {exc}")

    # The analyzers are constructed before NotificationManager for historical
    # startup ordering; wire the same instance into Direct Flow A explicitly.
    for analyzer in (app.state.ioc_investigator, app.state.malware_analyzer):
        if analyzer is not None:
            analyzer.notification_manager = app.state.notification_manager

    # Email and file-analysis pages are analyst-only and must not enter the
    # notification path used by the shared Flow A instances.  Shallow copies
    # preserve expensive RAG/intelligence resources while isolating mutable
    # wiring attributes.
    email_ana = getattr(app.state, 'email_analyzer', None)
    ioc_inv = getattr(app.state, 'ioc_investigator', None)
    mal_ana = getattr(app.state, 'malware_analyzer', None)
    if email_ana:
        email_ioc = copy(ioc_inv) if ioc_inv else None
        email_malware = copy(mal_ana) if mal_ana else None
        if email_ioc:
            email_ioc.notification_manager = None
        if email_malware:
            email_malware.notification_manager = None
            email_malware.ioc_investigator = email_ioc
        email_ana.ioc_investigator = email_ioc
        email_ana.file_analyzer = email_malware

    # Agent Loop
    try:
        from src.agent.agent_loop import AgentLoop
        app.state.agent_loop = AgentLoop(
            config=config,
            tool_registry=app.state.tool_registry or ToolRegistry(),
            agent_store=app.state.agent_store,
            mcp_client=app.state.mcp_client,
            llm_analyzer=app.state.llm_analyzer,
            notification_manager=app.state.notification_manager,
        )
        logger.info("[WEB] AgentLoop initialized")
    except Exception as exc:
        logger.warning(f"[WEB] AgentLoop not available: {exc}")

    # Playbook Engine
    try:
        from src.agent.playbook_engine import PlaybookEngine
        app.state.playbook_engine = PlaybookEngine(
            agent_loop=app.state.agent_loop,
            agent_store=app.state.agent_store,
            notification_manager=app.state.notification_manager,
        )
        # Wire playbook engine back into agent loop so LLM can trigger playbooks
        if app.state.agent_loop is not None:
            app.state.agent_loop._playbook_engine = app.state.playbook_engine
        logger.info("[WEB] PlaybookEngine initialized")
    except Exception as exc:
        logger.warning(f"[WEB] PlaybookEngine not available: {exc}")

    # Register routers
    app.include_router(dashboard.router, prefix='/api/dashboard', tags=['Dashboard'])
    app.include_router(analysis.router, prefix='/api/analysis', tags=['Analysis'])
    app.include_router(reports.router, prefix='/api/reports', tags=['Reports'])
    app.include_router(config_api.router, prefix='/api/config', tags=['Config'])
    app.include_router(cases.router, prefix='/api/cases', tags=['Cases'])
    app.include_router(agent_routes.router, prefix='/api/agent', tags=['Agent'])
    app.include_router(chat_routes.router, prefix='/api/chat', tags=['Chat'])
    app.include_router(playbook_routes.router, prefix='/api/playbooks', tags=['Playbooks'])
    app.include_router(mcp_routes.router, prefix='/api/mcp', tags=['MCP'])
    app.include_router(tickets.router, prefix='/api', tags=['Tickets'])
    app.include_router(auth_routes.router, prefix='/api/auth', tags=['Auth'])
    app.include_router(admin_routes.router, prefix='/api/admin', tags=['Admin'])
    app.include_router(
        admin_routes.team_lead_router,
        prefix='/api/team-lead',
        tags=['Team Lead'],
    )
    app.include_router(
        access_request_routes.router,
        prefix='/api/admin',
        tags=['Admin access requests'],
    )
    app.include_router(gmail_routes.router, prefix='/api/settings/gmail', tags=['Gmail OAuth'])
    app.include_router(account_api_keys_routes.router, prefix='/api/account', tags=['Account API keys'])
    app.include_router(helpdesk_routes.router, prefix='/api/helpdesk', tags=['Help Desk'])
    app.include_router(gmail_routes.admin_router, prefix='/api/admin', tags=['Admin Gmail OAuth'])
    app.include_router(websocket.router)

    # Page routes (HTML templates)
    _register_page_routes(app)

    logger.info("[WEB] Blue Team Assistant Web Dashboard initialized")
    return app


async def _auto_connect_mcp_servers(app: FastAPI) -> None:
    """Connect to MCP servers from config.yaml and AgentStore on startup."""
    mcp_client = getattr(app.state, 'mcp_client', None)
    if not mcp_client:
        return

    tool_registry = getattr(app.state, 'tool_registry', None)
    config = getattr(app.state, 'config', None) or {}
    mcp_servers = config.get('mcp_servers', []) if isinstance(config, dict) else []

    servers_to_connect = []
    seen_names = set()

    # 1. Collect from config.yaml (auto_connect: true or all config servers)
    for srv in mcp_servers:
        if isinstance(srv, dict) and srv.get('name'):
            if srv.get('auto_connect', True):
                servers_to_connect.append(srv)
                seen_names.add(srv['name'])

    # 2. Collect saved servers from AgentStore Database
    agent_store = getattr(app.state, 'agent_store', None)
    if agent_store and hasattr(agent_store, 'list_mcp_connections'):
        try:
            db_servers = agent_store.list_mcp_connections()
            for db_srv in db_servers:
                name = db_srv.get('name')
                if name and name not in seen_names:
                    cfg_dict = db_srv.get('config_json') or db_srv
                    if isinstance(cfg_dict, dict) and 'name' in cfg_dict:
                        servers_to_connect.append(cfg_dict)
                        seen_names.add(name)
        except Exception as db_exc:
            logger.warning("[WEB] Failed to fetch MCP connections from store: %s", db_exc)

    if not servers_to_connect:
        logger.info("[WEB] No MCP servers found to auto-connect")
        return

    logger.info("[WEB] Auto-connecting to %d MCP server(s)...", len(servers_to_connect))

    for srv_cfg in servers_to_connect:
        try:
            from src.agent.mcp_client import MCPServerConfig
            mcp_cfg = MCPServerConfig.from_dict(srv_cfg)
            success = await mcp_client.connect(mcp_cfg)
            if success:
                logger.info("[WEB] Connected to MCP server: %s", mcp_cfg.name)
                # Register MCP tools into the ToolRegistry so the LLM can see them
                if tool_registry:
                    try:
                        tools = await mcp_client.list_tools(mcp_cfg.name)
                        if tools:
                            tool_registry.register_mcp_tools(mcp_cfg.name, tools)
                            logger.info(
                                "[WEB] Registered %d MCP tools from %s into ToolRegistry",
                                len(tools), mcp_cfg.name
                            )
                    except Exception as te:
                        logger.warning(
                            "[WEB] Failed to register MCP tools for %s: %s",
                            mcp_cfg.name, te
                        )
            else:
                logger.warning("[WEB] Failed to connect to MCP server: %s", mcp_cfg.name)
        except Exception as exc:
            logger.warning(
                "[WEB] MCP auto-connect error for %s: %s",
                srv_cfg.get('name', '?'), exc
            )


def _register_page_routes(app: FastAPI) -> None:
    """Register HTML page routes for the dashboard."""
    from fastapi import Request
    from fastapi.responses import HTMLResponse

    templates = getattr(app.state, 'templates', None)
    if templates is None:
        templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
        app.state.templates = templates
        _register_brand_globals(templates)

    @app.get('/', response_class=HTMLResponse, include_in_schema=False)
    async def index(request: Request):
        redirect = _page_auth_redirect(request)
        if redirect is not None:
            return redirect
        return templates.TemplateResponse(request, 'agent_chat.html', {})

    @app.get('/login', response_class=HTMLResponse, include_in_schema=False)
    async def login_page(request: Request, next: str = '/'):
        next_path = safe_relative_path(next)
        user = _page_auth_user(request)
        if user is not None:
            if next_path == '/':
                next_path = ROLE_DEFAULT_LANDING.get(user.get('role'), '/dashboard')
            return RedirectResponse(url=next_path, status_code=303)
        return templates.TemplateResponse(request, 'login.html', {
            'next_path': next_path,
        })

    @app.get('/register', response_class=HTMLResponse, include_in_schema=False)
    @app.get('/accept-invite', response_class=HTMLResponse, include_in_schema=False)
    async def register_page(
        request: Request,
        token: str = '',
        next: str = '/login',
    ):
        next_path = safe_relative_path(next, default='/login')
        if _page_auth_user(request) is not None:
            return RedirectResponse(url=next_path, status_code=303)
        return templates.TemplateResponse(request, 'register.html', {
            'invite_token': token,
            'next_path': next_path,
        })

    def _request_access_context(
        *,
        error: str | None = None,
        submitted: bool = False,
        form_values: dict | None = None,
    ) -> dict:
        return {
            'roles': access_request_routes.REQUESTABLE_ROLES,
            'error': error,
            'submitted': submitted,
            'form_values': form_values or {},
        }

    @app.get('/request-access', response_class=HTMLResponse, include_in_schema=False)
    async def request_access_page(request: Request, submitted: bool = False):
        return templates.TemplateResponse(
            request,
            'request_access.html',
            _request_access_context(submitted=submitted),
        )

    @app.post('/request-access', response_class=HTMLResponse, include_in_schema=False)
    async def request_access_submit(
        request: Request,
        name: str = Form(''),
        email: str = Form(''),
        reason: str = Form(''),
    ):
        requested_role = access_request_routes.REQUESTABLE_ROLES[0]
        client_ip = request.client.host if request.client else 'unknown'
        limited, retry_after = access_request_routes.check_rate_limit(client_ip)
        form_values = {
            'name': name,
            'email': email,
            'requested_role': requested_role,
            'reason': reason,
        }
        if limited:
            return templates.TemplateResponse(
                request,
                'request_access.html',
                _request_access_context(
                    error='Too many requests. Please try again later.',
                    form_values=form_values,
                ),
                status_code=429,
                headers={'Retry-After': str(retry_after)},
            )

        normalized_name = name.strip()
        normalized_email = access_request_routes.normalize_email(email)
        normalized_reason = reason.strip()
        error = None
        if not normalized_name or len(normalized_name) > 120:
            error = 'Enter a name no longer than 120 characters.'
        elif not access_request_routes.is_valid_email(normalized_email):
            error = 'Enter a valid email address.'
        elif not normalized_reason or len(normalized_reason) > 1000:
            error = 'Enter a short reason no longer than 1000 characters.'

        if error:
            return templates.TemplateResponse(
                request,
                'request_access.html',
                _request_access_context(error=error, form_values=form_values),
                status_code=400,
            )

        try:
            access_request_routes.create_access_request(
                name=normalized_name,
                email=normalized_email,
                requested_role=requested_role,
                reason=normalized_reason,
            )
        except ValueError as exc:
            return templates.TemplateResponse(
                request,
                'request_access.html',
                _request_access_context(
                    error=str(exc),
                    form_values=form_values,
                ),
                status_code=409,
            )

        return RedirectResponse('/request-access?submitted=true', status_code=303)

    @app.get('/management', response_class=HTMLResponse, include_in_schema=False)
    async def management_page(
        request: Request,
        _current_user: dict = Depends(require_role(['admin', TEAM_LEAD])),
    ):
        is_admin = _current_user.get('role') == 'admin'
        pending_requests = (
            access_request_routes.list_pending_access_requests()
            if is_admin
            else []
        )
        return templates.TemplateResponse(
            request,
            'management.html',
            {
                'current_user': _current_user,
                'pending_requests': pending_requests,
                'team_member_roles': admin_routes.TEAM_MEMBER_INVITABLE_ROLES,
            },
        )

    @app.get('/dashboard', response_class=HTMLResponse, include_in_schema=False)
    async def dashboard_page(request: Request):
        redirect = _page_auth_redirect(request)
        if redirect is not None:
            return redirect
        current_user = getattr(request.state, 'user', None) or _page_auth_user(request)
        if current_user is None:
            return RedirectResponse('/login?next=%2Fdashboard', status_code=303)

        from .visibility import serialize_dashboard_job, serialize_dashboard_stats

        manager = app.state.analysis_manager
        role = current_user.get('role')
        stats = serialize_dashboard_stats(
            manager.get_stats(), role
        )
        if role == TEAM_LEAD:
            from .oversight import record_cross_user_read
            recent = manager.list_jobs(
                limit=10,
                user_ids=get_user_ids_by_role('SOC Analyst Tier 1-2'),
            )
            for job in recent:
                if job.get('user_id') != current_user.get('id'):
                    record_cross_user_read(
                        request,
                        actor_user_id=current_user['id'],
                        actor_role=TEAM_LEAD,
                        target_user_id=job.get('user_id'),
                        resource_type='dashboard',
                        resource_id=job.get('id'),
                    )
        else:
            recent = manager.list_jobs(
                limit=10,
                user_id=None if role == 'admin' else current_user.get('id'),
            )
        recent_jobs = [serialize_dashboard_job(job, role=role) for job in recent]
        return templates.TemplateResponse(request, 'dashboard.html', {
            'stats': stats, 'recent_jobs': recent_jobs,
        })

    @app.get('/soc-operations', response_class=HTMLResponse, include_in_schema=False)
    async def soc_operations_page(request: Request):
        return templates.TemplateResponse(request, 'soc_operations.html', {})

    @app.get('/analysis/ioc', response_class=HTMLResponse, include_in_schema=False)
    async def ioc_page(request: Request):
        return templates.TemplateResponse(request, 'analysis_ioc.html', {})

    @app.get('/analysis/file', response_class=HTMLResponse, include_in_schema=False)
    async def file_page(request: Request):
        from .upload_validation import FILE_ALLOWED_EXTENSIONS

        return templates.TemplateResponse(
            request,
            'analysis_file.html',
            {'allowed_extensions': sorted(FILE_ALLOWED_EXTENSIONS)},
        )

    @app.get('/analysis/email', response_class=HTMLResponse, include_in_schema=False)
    async def email_page(request: Request):
        return templates.TemplateResponse(request, 'analysis_email.html', {})

    @app.get('/history', response_class=HTMLResponse, include_in_schema=False)
    async def history_page(request: Request):
        current_user = getattr(request.state, "user", None)
        if not current_user:
            redirect = _page_auth_redirect(request)
            if redirect is not None:
                return redirect
            return RedirectResponse('/login?next=%2Fhistory', status_code=303)

        role = current_user.get("role")
        if role != "admin" and role != TEAM_LEAD and current_user.get("id") is None:
            redirect = _page_auth_redirect(request)
            if redirect is not None:
                return redirect
            return RedirectResponse('/login?next=%2Fhistory', status_code=303)
        return templates.TemplateResponse(request, 'history.html', {})

    @app.get('/cases', response_class=HTMLResponse, include_in_schema=False)
    async def cases_page(request: Request):
        case_list = app.state.case_store.list_cases(limit=100)
        return templates.TemplateResponse(request, 'cases.html', {
            'cases': case_list,
        })

    @app.get('/cases/{case_id}', response_class=HTMLResponse, include_in_schema=False)
    async def case_detail_page(request: Request, case_id: str):
        case = app.state.case_store.get_case(case_id)
        if not case:
            return HTMLResponse('<h3>Case not found</h3>', status_code=404)
        return templates.TemplateResponse(request, 'case_detail.html', {
            'case': case,
        })

    @app.get('/tickets', response_class=HTMLResponse, include_in_schema=False)
    async def tickets_page(
        request: Request,
        current_user: dict = Depends(get_current_user),
    ):
        from src.integrations.ticketing import get_all_tickets
        import json as _json
        try:
            raw_tickets = get_all_tickets(
                owner_id=tickets.ticket_owner_scope(current_user)
            )
        except Exception as e:
            logger.warning(f"[WEB] Failed to load tickets: {e}")
            raw_tickets = []
        ticket_rows = []
        for t in raw_tickets:
            t = dict(t)
            recs = t.get('recommendations')
            if isinstance(recs, str):
                try:
                    t['recommendations'] = _json.loads(recs)
                except Exception:
                    t['recommendations'] = []
            ticket_rows.append(t)
        return templates.TemplateResponse(request, 'tickets.html', {
            'tickets': ticket_rows,
        })
    @app.get('/report/{job_id}', response_class=HTMLResponse, include_in_schema=False)
    async def report_page(request: Request, job_id: str):
        job = app.state.analysis_manager.get_job(job_id)
        if not job:
            return HTMLResponse('<h3>Report not found</h3>', status_code=404)
        # Redirect to the serialized report endpoint for visibility filtering.
        target = f"/api/reports/{quote(job_id, safe='')}/html"
        if request.url.query:
            target += f"?{request.url.query}"
        return RedirectResponse(url=target, status_code=307)

    # ----- Agent pages -----

    @app.get('/agent/chat', response_class=HTMLResponse, include_in_schema=False)
    async def agent_chat_page(request: Request):
        return templates.TemplateResponse(request, 'agent_chat.html', {})

    @app.get('/agent/investigations', response_class=HTMLResponse, include_in_schema=False)
    async def agent_investigations_page(request: Request):
        sessions = []
        stats = {"total": 0, "active": 0, "completed": 0, "failed": 0}
        current_user = getattr(request.state, 'user', None) or _page_auth_user(request)
        if current_user is None:
            return RedirectResponse('/login?next=%2Fagent%2Finvestigations', status_code=303)
        role = current_user.get('role')
        owner_id = None if role == 'admin' else current_user.get('id')
        if app.state.agent_store:
            sessions = app.state.agent_store.list_sessions(
                limit=100, user_id=owner_id
            )
            stats = app.state.agent_store.get_agent_stats(user_id=owner_id)
        return templates.TemplateResponse(request, 'agent_investigations.html', {
            'sessions': sessions, 'stats': stats,
        })

    @app.get('/agent/playbooks', response_class=HTMLResponse, include_in_schema=False)
    async def agent_playbooks_page(request: Request):
        playbooks = []
        if app.state.playbook_engine:
            playbooks = app.state.playbook_engine.list_playbooks()
        elif app.state.agent_store:
            playbooks = app.state.agent_store.list_playbooks()
        return templates.TemplateResponse(request, 'playbooks.html', {
            'playbooks': playbooks,
        })

    @app.get('/integrations', response_class=HTMLResponse, include_in_schema=False)
    async def integrations_page(request: Request):
        redirect = _page_auth_redirect(request)
        if redirect is not None:
            return redirect
        return templates.TemplateResponse(request, 'integrations_hub.html', {})

    @app.get('/integrations/wazuh', response_class=HTMLResponse, include_in_schema=False)
    async def wazuh_integration_page(request: Request):
        redirect = _page_auth_redirect(request)
        if redirect is not None:
            return redirect
        return templates.TemplateResponse(request, 'integrations_wazuh.html', {})

    @app.get('/api/integrations/status', include_in_schema=False)
    async def integrations_status(
        request: Request,
        _current_user: dict = Depends(require_role(["Incident Responder", "admin"])),
    ):
        from .settings_registry import settings_sources

        config = getattr(request.app.state, 'config', None) or {}
        api_keys = config.get('api_keys', {}) if isinstance(config, dict) else {}
        source_status = {
            item['id']: bool(item['configured'])
            for item in settings_sources(api_keys if isinstance(api_keys, dict) else {})
        }
        threat_intel = [
            {'name': name, 'configured': source_status[source_id]}
            for name, source_id in (
                ('VirusTotal', 'virustotal'),
                ('AbuseIPDB', 'abuseipdb'),
                ('Shodan', 'shodan'),
                ('AlienVault OTX', 'alienvault'),
                ('GreyNoise', 'greynoise'),
            )
        ]
        threat_intel.append({'name': 'URLScan', 'configured': None})
        sandboxes = [
            {'name': name, 'configured': source_status[source_id]}
            for name, source_id in (
                ('Triage', 'triage'),
                ('ThreatZone', 'threatzone'),
                ('Hybrid Analysis', 'hybrid_analysis'),
                ('ANY.RUN', 'anyrun'),
            )
        ]

        store = getattr(request.app.state, 'agent_store', None)
        db_servers = store.list_mcp_connections() if store else []
        config_servers = config.get('mcp_servers', []) if isinstance(config, dict) else []
        merged_names = set()
        for server in config_servers:
            name = server.get('name', '') if isinstance(server, dict) else ''
            if name:
                merged_names.add(name)
        merged_names.update(server['name'] for server in db_servers if server.get('name'))

        connected_count = None
        mcp_client = getattr(request.app.state, 'mcp_client', None)
        if mcp_client:
            try:
                live_status = mcp_client.get_connection_status()
                connected_count = sum(
                    1 for name in merged_names
                    if isinstance(live_status.get(name), dict)
                    and live_status[name].get('connected') is True
                )
            except Exception:
                connected_count = None

        return {
            'threat_intel': threat_intel,
            'sandboxes': sandboxes,
            'mcp': {
                'configured_count': len(merged_names),
                'connected_count': connected_count,
            },
        }

    @app.get('/api/integrations/wazuh/download', include_in_schema=False)
    async def download_wazuh_integration(
        _current_user: dict = Depends(require_role(["Incident Responder", "admin"]))
    ):
        bundle_root = PROJECT_ROOT / 'deploy' / 'wazuh'
        bundle_files = [
            bundle_root / 'README.md',
            bundle_root / 'custom-cabta',
            bundle_root / 'ossec.conf',
            *sorted((bundle_root / 'samples').glob('*.json')),
        ]
        archive = BytesIO()
        with ZipFile(archive, 'w', compression=ZIP_DEFLATED) as zip_file:
            for bundle_file in bundle_files:
                if not bundle_file.is_file():
                    continue
                archive_name = Path('cabta-wazuh-integration') / bundle_file.relative_to(bundle_root)
                zip_file.write(bundle_file, archive_name.as_posix())
        return Response(
            content=archive.getvalue(),
            media_type='application/zip',
            headers={'Content-Disposition': 'attachment; filename="cabta-wazuh-integration.zip"'},
        )

    @app.get('/mcp/servers', response_class=HTMLResponse, include_in_schema=False)
    async def mcp_servers_page(
        request: Request,
        _current_user: dict = Depends(require_role("admin")),
    ):
        db_servers = []
        if app.state.agent_store:
            db_servers = app.state.agent_store.list_mcp_connections()

        # Merge config.yaml servers with DB servers
        db_lookup = {s['name']: s for s in db_servers}
        config_obj = getattr(app.state, 'config', None) or {}
        config_servers = config_obj.get('mcp_servers', []) if isinstance(config_obj, dict) else []

        merged = []
        seen_names = set()
        for cfg in config_servers:
            name = cfg.get('name', '')
            if not name:
                continue
            entry = dict(cfg)
            if name in db_lookup:
                db_entry = db_lookup[name]
                entry.update({k: v for k, v in db_entry.items() if v is not None})
            entry.setdefault('source', 'config')
            entry.setdefault('status', 'disconnected')
            merged.append(entry)
            seen_names.add(name)
        for s in db_servers:
            if s['name'] not in seen_names:
                s.setdefault('source', 'user')
                s.setdefault('status', 'requires_install')
                merged.append(s)

        # Add live status if MCP client is available
        if hasattr(app.state, 'mcp_client') and app.state.mcp_client:
            try:
                live_status = app.state.mcp_client.get_connection_status()
                for s in merged:
                    s['live_status'] = live_status.get(s['name'], {})
            except Exception:
                pass

        # Category metadata for grouping/filtering
        from src.web.routes.mcp_management import CATEGORY_META, _server_category, _server_display
        categories = CATEGORY_META

        # Collect unique categories present in the server list
        active_categories = []
        seen_cats = set()
        tools_total = 0
        connected_count = 0
        attention_count = 0
        for s in merged:
            cat = _server_category(s)
            s['category'] = cat
            s.update(_server_display(s))
            live_status = s.get('live_status') or {}
            tool_count = live_status.get('tool_count', 0) if isinstance(live_status, dict) else 0
            tools_total += tool_count if isinstance(tool_count, int) and not isinstance(tool_count, bool) else 0
            is_connected = isinstance(live_status, dict) and live_status.get('connected') is True
            if is_connected:
                connected_count += 1
            status = str(s.get('status') or '').lower()
            if status.startswith('error') or (isinstance(live_status, dict) and live_status.get('connected') is False):
                attention_count += 1
            if cat not in seen_cats:
                seen_cats.add(cat)
                meta = categories.get(cat, {'label': cat.replace('_', ' ').title(), 'icon': 'bi-server'})
                active_categories.append({'key': cat, **meta})

        return templates.TemplateResponse(request, 'mcp_servers.html', {
            'servers': merged,
            'categories': categories,
            'active_categories': active_categories,
            'tools_total': tools_total,
            'connected_count': connected_count,
            'attention_count': attention_count,
        })

    @app.get('/settings', response_class=HTMLResponse, include_in_schema=False)
    async def settings_page(request: Request):
        redirect = _page_auth_redirect(request)
        if redirect is not None:
            return redirect
        return templates.TemplateResponse(request, 'settings.html', {})

    @app.get('/account', response_class=HTMLResponse, include_in_schema=False)
    async def account_page(request: Request):
        redirect = _page_auth_redirect(request)
        if redirect is not None:
            return redirect
        return templates.TemplateResponse(request, 'account.html', {})
