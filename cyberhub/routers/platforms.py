"""
Cyber Hub Backend - Social & Platform Accounts routes (Part 16)
Developed by Syed Muhammad Tayyab

Every route needs the API token + a signed-in, unlocked Cyber Hub session. Accounts, e-mails and checklists are
per Cyber Hub user.

Catalog:   GET /catalog, GET /catalog/{key}
Accounts:  GET/POST /accounts, GET/PATCH/DELETE /accounts/{id}, PUT /accounts/{id}/checklist,
           POST /accounts/{id}/reviewed, GET /accounts/{id}/vault-matches, POST /accounts/{id}/vault-link,
           POST/DELETE /accounts/{id}/github, POST /accounts/{id}/github/sync, GET /recovery-graph, POST /discover
E-mails:   GET/POST /emails, GET/PATCH/DELETE /emails/{id}, POST /emails/check (job), POST /emails/{id}/ack,
           GET /emails/suggest, GET /jobs/{id}
Breaches:  GET /breaches (public HIBP list), POST /breaches/refresh, GET /providers, PUT /providers/hibp/key
Links:     POST /check-link {value, platform?}  - "is this really from Facebook?"
Extensions: GET /extensions, POST /extensions/scan
Alerts:    GET /events, POST /events/ack, DELETE /events, WebSocket /stream

Errors: 403 admin / switched off, 404 not found, 409 conflict (duplicate, job running, key refused), 413 too many,
422 bad input, 423 password vault locked, 429 rate limit (Retry-After), 501/503 module / device key unavailable.
"""
from __future__ import annotations

import asyncio
import hmac
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from ..security import CurrentUser, require_admin, require_session, require_token
from ..services.platform_accounts import PlatformError, PlatformService

router = APIRouter(prefix="/api/platforms", tags=["platforms"],
                   dependencies=[Depends(require_token), Depends(require_session)])
stream_router = APIRouter(prefix="/api/platforms", tags=["platforms"])

Sev = Literal["info", "low", "medium", "high", "critical"]
Imp = Literal["critical", "high", "medium", "low"]


def _ps(request: Request) -> PlatformService:
    return request.app.state.platforms


def _run(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except PlatformError as e:
        headers = {"Retry-After": str(e.retry_after)} if e.retry_after else None
        raise HTTPException(e.status, e.message, headers=headers)


# ================================================================== overview
@router.get("/status")
def status(request: Request, cu: CurrentUser = Depends(require_session)):
    """Platforms card: features, settings, health (score, 2FA coverage, breached e-mails, risky extensions),
    breach providers, breach-list state, running check, unread alerts."""
    return _ps(request).status(cu)


@router.get("/health")
def health(request: Request, cu: CurrentUser = Depends(require_session)):
    return _ps(request).health(cu.user["id"])


@router.get("/summary")
def summary(request: Request, days: int = Query(30, ge=1, le=365), cu: CurrentUser = Depends(require_session)):
    """Graphs: accounts + 2FA by category, importance, checklist completion, score history, breaches per year,
    alerts per day, recovery graph."""
    return _ps(request).summary(cu, days)


@router.get("/catalog")
def catalog(request: Request):
    """Every known platform: official domains, 2FA / recovery options, security page links, tips + checklist items."""
    return _ps(request).catalog()


@router.get("/catalog/{key}")
def catalog_one(request: Request, key: str):
    return _run(_ps(request).platform, key)


# ================================================================== accounts
class AccountIn(BaseModel):
    platform: str = Field(..., min_length=1, max_length=40, description="catalog key or 'custom'")
    label: str | None = Field(None, max_length=60, description="e.g. Personal / Work")
    handle: str | None = Field(None, max_length=200, description="user name / profile handle")
    email: str | None = Field(None, max_length=320, description="sign-in e-mail (monitored for breaches)")
    phone_last4: str | None = Field(None, max_length=4, description="ONLY the last 2-4 digits of the phone")
    notes: str | None = Field(None, max_length=1000)
    importance: Imp | None = None
    custom_name: str | None = Field(None, max_length=80)
    custom_domain: str | None = Field(None, max_length=253)
    recovery_account_id: int | None = None
    sso_account_id: int | None = None
    vault_item_id: str | None = Field(None, max_length=64)


@router.get("/accounts")
def accounts(request: Request, category: str | None = Query(None, max_length=40),
             q: str | None = Query(None, max_length=200), issue: str | None = Query(None, max_length=40),
             cu: CurrentUser = Depends(require_session)):
    """Your accounts, worst first: score, 2FA state, top issues, overview score."""
    return _ps(request).list_accounts(cu, category, q, issue)


@router.post("/accounts", status_code=201)
def add_account(request: Request, body: AccountIn, cu: CurrentUser = Depends(require_session)):
    data = body.model_dump(exclude={"platform"}, exclude_unset=True)
    return _run(_ps(request).add_account, cu, body.platform, data)


@router.get("/accounts/{aid}")
def account(request: Request, aid: int, cu: CurrentUser = Depends(require_session)):
    """Full detail: checklist with where each answer came from (you / vault / github / breach), issues, recovery
    chain, the site's breaches, e-mail breaches, vault + GitHub state."""
    return _run(_ps(request).get_account, cu, aid)


class AccountPatch(BaseModel):
    label: str | None = Field(None, max_length=60)
    handle: str | None = Field(None, max_length=200)
    email: str | None = Field(None, max_length=320)
    phone_last4: str | None = Field(None, max_length=4)
    notes: str | None = Field(None, max_length=1000)
    importance: Imp | None = None
    custom_name: str | None = Field(None, max_length=80)
    custom_domain: str | None = Field(None, max_length=253)
    recovery_account_id: int | None = None
    sso_account_id: int | None = None


@router.patch("/accounts/{aid}")
def update_account(request: Request, aid: int, body: AccountPatch, cu: CurrentUser = Depends(require_session)):
    return _run(_ps(request).update_account, cu, aid, body.model_dump(exclude_unset=True))


@router.delete("/accounts/{aid}")
def delete_account(request: Request, aid: int, cu: CurrentUser = Depends(require_session)):
    return _run(_ps(request).delete_account, cu, aid)


class ChecklistIn(BaseModel):
    items: dict[str, Literal["done", "not_done", "not_applicable", "unknown"]] = Field(..., min_length=1)
    note: str | None = Field(None, max_length=300)


@router.put("/accounts/{aid}/checklist")
def checklist(request: Request, aid: int, body: ChecklistIn, cu: CurrentUser = Depends(require_session)):
    """Tick checklist items. Facts from the vault / GitHub / breach data override ticks for the same item."""
    return _run(_ps(request).set_checks, cu, aid, body.items, body.note)


@router.post("/accounts/{aid}/reviewed")
def reviewed(request: Request, aid: int, cu: CurrentUser = Depends(require_session)):
    """'I just checked devices / apps / keys / privacy' - resets the review timer."""
    return _run(_ps(request).mark_reviewed, cu, aid)


@router.get("/accounts/{aid}/vault-matches")
def vault_matches(request: Request, aid: int, cu: CurrentUser = Depends(require_session)):
    """Logins in your (unlocked) password vault for this platform's sites."""
    return _run(_ps(request).vault_matches, cu, aid)


class VaultLinkIn(BaseModel):
    item_id: str | None = Field(None, max_length=64, description="null = unlink")
    create: bool = Field(False, description="Create a new vault login for this account (vault must be unlocked)")
    password: str | None = Field(None, max_length=1024, description="with create: the current password")


@router.post("/accounts/{aid}/vault-link")
def vault_link(request: Request, aid: int, body: VaultLinkIn, cu: CurrentUser = Depends(require_session)):
    return _run(_ps(request).link_vault, cu, aid, body.item_id, body.create, body.password)


class GithubIn(BaseModel):
    token: str = Field(..., min_length=10, max_length=300)
    allow_broad: bool = Field(False, description="Accept a token that can also write (not recommended)")


@router.post("/accounts/{aid}/github")
def github_connect(request: Request, aid: int, body: GithubIn, cu: CurrentUser = Depends(require_session)):
    """Connect a GitHub account with a READ-ONLY token: 2FA on / off and SSH key age come straight from GitHub."""
    return _run(_ps(request).connect_github, cu, aid, body.token, body.allow_broad)


@router.post("/accounts/{aid}/github/sync")
def github_sync(request: Request, aid: int, cu: CurrentUser = Depends(require_session)):
    return _run(_ps(request).sync_github, cu, aid)


@router.delete("/accounts/{aid}/github")
def github_disconnect(request: Request, aid: int, cu: CurrentUser = Depends(require_session)):
    return _run(_ps(request).disconnect, cu, aid)


@router.get("/recovery-graph")
def recovery_graph(request: Request, cu: CurrentUser = Depends(require_session)):
    """Nodes = accounts, edges = 'can reset' (recovery e-mail) and 'signs in' (Google / Microsoft / GitHub login).
    hubs = accounts that can reset others, weak_hubs = those without 2FA."""
    return _ps(request).recovery_graph(cu)


class DiscoverIn(BaseModel):
    sources: list[Literal["vault", "apps"]] | None = None
    create: bool = Field(False, description="Add the suggestions that aren't in your list yet")
    platforms: list[str] | None = Field(None, max_length=100, description="with create: only these")


@router.post("/discover")
def discover(request: Request, body: DiscoverIn, cu: CurrentUser = Depends(require_session)):
    """Find your accounts: logins in the unlocked password vault + apps running on this PC."""
    return _run(_ps(request).discover, cu, body.sources, body.create, body.platforms)


# ================================================================== link / sender check
class LinkIn(BaseModel):
    value: str = Field(..., min_length=1, max_length=2048, description="link, web address or sender e-mail")
    platform: str | None = Field(None, max_length=40, description="who the message claims to be from")
    deep: bool = Field(False, description="Open the page read-only and look closer (Part 15 deep check)")


@router.post("/check-link")
def check_link(request: Request, body: LinkIn, cu: CurrentUser = Depends(require_session)):
    """Is this link / sender really from that platform? Official-domain check + threat feeds + phishing analysis."""
    return _run(_ps(request).check_link, cu, body.value, body.platform, body.deep)


# ================================================================== e-mails
@router.get("/emails")
def emails(request: Request, cu: CurrentUser = Depends(require_session)):
    return _ps(request).emails(cu)


@router.get("/emails/suggest")
def suggest_emails(request: Request, cu: CurrentUser = Depends(require_session)):
    return _ps(request).suggest_emails(cu)


class EmailIn(BaseModel):
    email: str = Field(..., min_length=3, max_length=320)
    monitor: bool = True


@router.post("/emails", status_code=201)
def add_email(request: Request, body: EmailIn, cu: CurrentUser = Depends(require_session)):
    return _run(_ps(request).add_email, cu, body.email, body.monitor)


@router.get("/emails/{eid}")
def email(request: Request, eid: int, reveal: bool = False, cu: CurrentUser = Depends(require_session)):
    """One address with its breaches (what leaked, when, what to do). reveal=true shows the full address."""
    return _run(_ps(request).email, cu, eid, reveal)


class EmailPatch(BaseModel):
    monitor: bool


@router.patch("/emails/{eid}")
def patch_email(request: Request, eid: int, body: EmailPatch, cu: CurrentUser = Depends(require_session)):
    return _run(_ps(request).update_email, cu, eid, body.monitor)


@router.delete("/emails/{eid}")
def delete_email(request: Request, eid: int, cu: CurrentUser = Depends(require_session)):
    return _run(_ps(request).delete_email, cu, eid)


class CheckEmailsIn(BaseModel):
    ids: list[int] | None = Field(None, max_length=50, description="default: all your addresses")


@router.post("/emails/check")
def check_emails(request: Request, body: CheckEmailsIn, cu: CurrentUser = Depends(require_session)):
    """Ask the breach provider about your addresses now (background job - poll /jobs/{id}). Sends only the address."""
    return _run(_ps(request).check_emails, cu, body.ids)


class AckBreachIn(BaseModel):
    names: list[str] | None = Field(None, max_length=500)


@router.post("/emails/{eid}/ack")
def ack_breaches(request: Request, eid: int, body: AckBreachIn, cu: CurrentUser = Depends(require_session)):
    """'I've dealt with it' (changed the password) - the breach stops lowering your score."""
    return _run(_ps(request).acknowledge_breaches, cu, eid, body.names)


@router.get("/jobs/{job_id}")
def job(request: Request, job_id: str):
    return _run(_ps(request).job, job_id)


# ================================================================== breach list + providers
@router.get("/breaches")
def breaches(request: Request, q: str | None = Query(None, max_length=100),
             domain: str | None = Query(None, max_length=253), limit: int = Query(50, ge=1, le=500),
             offset: int = Query(0, ge=0)):
    """Search the public breach list (newest first)."""
    return _ps(request).breaches(q, domain, limit, offset)


@router.post("/breaches/refresh")
def refresh_breaches(request: Request, force: bool = False):
    """Download the public Have I Been Pwned breach list now (no personal data is sent)."""
    return _run(_ps(request).refresh_catalog, force)


@router.get("/providers")
def providers(request: Request):
    return _ps(request).providers()


class KeyIn(BaseModel):
    key: str | None = Field(None, max_length=64, description="Empty / null = remove")


@router.put("/providers/{provider}/key")
def set_key(request: Request, provider: str, body: KeyIn, cu: CurrentUser = Depends(require_admin)):
    """Admin: Have I Been Pwned API key (paid, from haveibeenpwned.com/API/Key) - stored encrypted."""
    return _run(_ps(request).set_key, cu, provider, body.key)


# ================================================================== extensions
@router.get("/extensions")
def extensions(request: Request, refresh: bool = False):
    """Browser + code-editor extensions on this PC with a risk score and what makes them risky."""
    return _ps(request).extensions(refresh)


class ExtScanIn(BaseModel):
    key: str = Field(..., min_length=3, max_length=600)


@router.post("/extensions/scan")
def scan_extension(request: Request, body: ExtScanIn, cu: CurrentUser = Depends(require_session)):
    """Scan an extension's folder with the antivirus (Part 5 custom scan)."""
    return _run(_ps(request).scan_extension, cu, body.key)


# ================================================================== events
@router.get("/events")
def events(request: Request, after_id: int = Query(0, ge=0), severity: Sev | None = None,
           kind: str | None = Query(None, max_length=40), unacknowledged: bool = False,
           limit: int = Query(100, ge=1, le=1000), cu: CurrentUser = Depends(require_session)):
    """Alerts: e-mail breaches, breached sites you use, GitHub 2FA off / old keys, reviews due, weak recovery
    accounts, new risky extensions."""
    return _ps(request).events(cu, after_id, severity, kind, unacknowledged, limit)


class AckIn(BaseModel):
    ids: list[int] | None = Field(None, max_length=1000)


@router.post("/events/ack")
def ack(request: Request, body: AckIn, cu: CurrentUser = Depends(require_session)):
    return {"acknowledged": _ps(request).acknowledge(cu, body.ids)}


@router.delete("/events")
def clear_events(request: Request, cu: CurrentUser = Depends(require_session)):
    return {"deleted": _ps(request).clear_events(cu)}


# ================================================================== WebSocket
@stream_router.websocket("/stream")
async def stream(ws: WebSocket, token: str = Query(""), session: str = Query("")):
    """Pushes {type:"platforms", job:{running breach check}, events:[new platform_events], unacknowledged}."""
    app = ws.app
    from ..services.accounts import AuthError

    def check_session():
        try:
            _s, u = app.state.accounts.authenticate(session, allow_locked=False, touch=False)
            return None, u
        except AuthError as e:
            return (4423 if e.status == 423 else 4401), None

    if not hmac.compare_digest(token, app.state.api_token):
        await ws.close(code=4401)
        return
    code, user = check_session()
    if code:
        await ws.close(code=code)
        return
    await ws.accept()
    svc: PlatformService = app.state.platforms

    class _CU:
        def __init__(self, u: dict[str, Any]):
            self.user = u
    cu = _CU(user)
    last_id = svc.events(cu, limit=1)["last_id"]
    ticks = 0
    try:
        while True:
            if ticks % 2 == 0:
                ev = svc.events(cu, after_id=last_id, limit=50)
                if ev["items"]:
                    last_id = max(e["id"] for e in ev["items"])
                await ws.send_json({"type": "platforms", "job": svc._running_job(),
                                    "events": list(reversed(ev["items"])), "unacknowledged": ev["unacknowledged"]})
            await asyncio.sleep(0.5)
            ticks += 1
            if ticks % 20 == 0:
                code, _ = check_session()
                if code:
                    await ws.send_json({"type": "closed", "reason": "locked" if code == 4423 else "signed_out"})
                    await ws.close(code=code)
                    return
    except (WebSocketDisconnect, RuntimeError):
        pass
