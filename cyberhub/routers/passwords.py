"""
Cyber Hub Backend - Password Vault & Auditor routes (Part 12)
Developed by Syed Muhammad Tayyab

Every route needs the API token + a signed-in, unlocked Cyber Hub session.
The vault belongs to the signed-in user only - administrators can't open
anyone else's vault. Item routes also need the vault unlocked with the
master password (423 "Password vault is locked" otherwise; the UI shows its
unlock screen). Wrong master passwords: 5 free tries, then 429 with
Retry-After. Plain-text CSV export and deleting the vault answer 428 until
sent again with confirm=true.

Secrets are masked in responses unless asked for (?reveal=true), and are
never written to logs, events or the activity list.
"""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from ..security import CurrentUser, require_session, require_token
from ..services.password_io import FORMATS
from ..services.password_vault import SEVERITIES, TYPES, PasswordVaultService, PVError

router = APIRouter(prefix="/api/passwords", tags=["passwords"],
                   dependencies=[Depends(require_token), Depends(require_session)])

ISSUES = "^(breached|reused|weak|fair|empty_password|insecure_url|old|duplicate|expired_card)$"


def _pv(request: Request) -> PasswordVaultService:
    return request.app.state.passwords


def _run(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except PVError as e:
        headers = {"Retry-After": str(e.retry_after)} if e.retry_after else None
        raise HTTPException(e.status, e.message, headers=headers)


# ================================================================== vault
@router.get("/status")
def status(request: Request, cu: CurrentUser = Depends(require_session)):
    """Vault card: exists / unlocked, items per type, trash, device-bound, auto-lock countdown, last audit
    (score, grade, counts), breach-check job, unread alerts, clipboard support."""
    return _pv(request).status(cu)


class SetupIn(BaseModel):
    master_password: str = Field(..., min_length=1, max_length=256)
    hint: str | None = Field(None, max_length=200)


@router.post("/setup")
def setup(request: Request, body: SetupIn, cu: CurrentUser = Depends(require_session)):
    """Create your vault. Returns the recovery key ONCE - the UI must show it and ask the user to save it."""
    return _run(_pv(request).setup, cu, body.master_password, body.hint)


class UnlockIn(BaseModel):
    master_password: str | None = Field(None, max_length=256)
    recovery_key: str | None = Field(None, max_length=64)
    new_master_password: str | None = Field(None, max_length=256, description="required with recovery_key")


@router.post("/unlock")
def unlock(request: Request, body: UnlockIn, cu: CurrentUser = Depends(require_session)):
    """Unlock with the master password, or with the recovery key + a new master password (a new recovery key is
    returned). 401 wrong, 429 too many tries (Retry-After), 503 device key missing -> use the recovery key."""
    return _run(_pv(request).unlock, cu, body.master_password, body.recovery_key, body.new_master_password)


@router.post("/lock")
def lock(request: Request, cu: CurrentUser = Depends(require_session)):
    return _pv(request).lock(cu)


@router.get("/hint")
def hint(request: Request, cu: CurrentUser = Depends(require_session)):
    return _run(_pv(request).hint, cu)


class MasterIn(BaseModel):
    current_master_password: str = Field(..., max_length=256)
    new_master_password: str = Field(..., max_length=256)
    hint: str | None = Field(None, max_length=200, description="omit to keep the old hint, '' to remove it")


@router.post("/master-password")
def change_master(request: Request, body: MasterIn, cu: CurrentUser = Depends(require_session)):
    """Change the master password (items are not re-encrypted: only the vault key is re-wrapped). Locks the vault
    in your other open windows."""
    return _run(_pv(request).change_master, cu, body.current_master_password, body.new_master_password,
                body.hint, body.hint is None)


class MasterOnlyIn(BaseModel):
    master_password: str = Field(..., max_length=256)


@router.post("/recovery-key")
def recovery_key(request: Request, body: MasterOnlyIn, cu: CurrentUser = Depends(require_session)):
    """Issue a new recovery key (the old one stops working). Shown once."""
    return _run(_pv(request).new_recovery_key, cu, body.master_password)


class DeleteVaultIn(BaseModel):
    account_password: str = Field(..., max_length=256, description="your Cyber Hub sign-in password")
    confirm: bool = False


@router.post("/vault/delete")
def delete_vault(request: Request, body: DeleteVaultIn, cu: CurrentUser = Depends(require_session)):
    """Forgot the master password AND lost the recovery key? Destroy the vault and start again (428 = confirm)."""
    return _run(_pv(request).delete_vault, cu, body.account_password, body.confirm)


# ================================================================== items
@router.get("/items")
def list_items(request: Request, cu: CurrentUser = Depends(require_session),
               q: str | None = Query(None, max_length=200),
               type: str | None = Query(None, pattern="^(" + "|".join(TYPES) + ")$"),
               folder: str | None = Query(None, max_length=60), favorite: bool | None = None, trash: bool = False,
               issue: str | None = Query(None, pattern=ISSUES)):
    """List without secrets: title, user name, host, folder, favorite, has 2FA, card brand + last 4, strength,
    reused count, breach count and issues[] per item. Favorites first, then A-Z."""
    return _run(_pv(request).list_items, cu, q, type, folder, favorite, trash, issue)


class ItemIn(BaseModel):
    type: Literal["login", "card", "note", "identity"]
    data: dict[str, Any] = Field(..., description="title (required), notes, folder, favorite, tags, fields[] + "
                                                  "login: username, password, urls[], totp | card: cardholder, "
                                                  "number, exp_month, exp_year, cvv | identity: full_name, email, "
                                                  "phone, address, company, national_id")


@router.post("/items")
def create_item(request: Request, body: ItemIn, cu: CurrentUser = Depends(require_session)):
    """Returns {item, warnings[]} - e.g. reused / weak password, http:// address, card number typo."""
    return _run(_pv(request).create_item, cu, body.type, body.data)


@router.get("/items/{item_id}")
def get_item(request: Request, item_id: str, reveal: bool = False, cu: CurrentUser = Depends(require_session)):
    """One item. Password, CVV, card number, national ID, 2FA secret and hidden fields are masked unless
    reveal=true."""
    return _run(_pv(request).get_item, cu, item_id, reveal)


@router.patch("/items/{item_id}")
def update_item(request: Request, item_id: str, data: dict[str, Any], cu: CurrentUser = Depends(require_session)):
    """Partial update. Masked values sent back unchanged are ignored. A changed password goes into the item's
    password history (last 10)."""
    return _run(_pv(request).update_item, cu, item_id, data)


@router.delete("/items/{item_id}")
def delete_item(request: Request, item_id: str, permanent: bool = False, cu: CurrentUser = Depends(require_session)):
    """Move to the trash (kept pv_trash_days), or delete for good with permanent=true."""
    return _run(_pv(request).delete_item, cu, item_id, permanent)


@router.post("/items/{item_id}/restore")
def restore_item(request: Request, item_id: str, cu: CurrentUser = Depends(require_session)):
    return _run(_pv(request).restore_item, cu, item_id)


@router.delete("/trash")
def empty_trash(request: Request, cu: CurrentUser = Depends(require_session)):
    return _run(_pv(request).empty_trash, cu)


@router.get("/items/{item_id}/history")
def item_history(request: Request, item_id: str, cu: CurrentUser = Depends(require_session)):
    """Previous passwords of a login (newest first, last 10)."""
    return _run(_pv(request).history, cu, item_id)


@router.get("/items/{item_id}/totp")
def item_totp(request: Request, item_id: str, cu: CurrentUser = Depends(require_session)):
    """Current 2FA code {code, remaining, period, digits, issuer} - poll when remaining reaches 0."""
    return _run(_pv(request).totp, cu, item_id)


class CopyIn(BaseModel):
    field: str = Field("password", pattern="^(password|username|totp|url|number|cvv|cardholder|email|phone|"
                                           "national_id|full_name|address|notes)$")


@router.post("/items/{item_id}/copy")
def copy(request: Request, item_id: str, body: CopyIn | None = None, cu: CurrentUser = Depends(require_session)):
    """Copy to the system clipboard, kept out of Win+V history / cloud clipboard, wiped after
    pv_clipboard_clear_seconds if still ours. 501 = no system clipboard: use the browser clipboard instead."""
    return _run(_pv(request).copy, cu, item_id, (body or CopyIn()).field)


@router.post("/clipboard/clear")
def clear_clipboard(request: Request):
    return _pv(request).clear_clipboard()


@router.get("/folders")
def folders(request: Request, cu: CurrentUser = Depends(require_session)):
    return _run(_pv(request).folders, cu)


class FolderRenameIn(BaseModel):
    old: str = Field(..., max_length=60)
    new: str = Field("", max_length=60, description="'' removes the folder (items stay, unfiled)")


@router.post("/folders/rename")
def rename_folder(request: Request, body: FolderRenameIn, cu: CurrentUser = Depends(require_session)):
    return _run(_pv(request).rename_folder, cu, body.old, body.new)


# ================================================================== tools (no unlock needed)
class GenerateIn(BaseModel):
    mode: Literal["password", "passphrase", "pin"] = "password"
    length: int | None = Field(None, ge=4, le=128)
    lower: bool = True
    upper: bool = True
    digits: bool = True
    symbols: bool = True
    avoid_ambiguous: bool = True
    exclude: str | None = Field(None, max_length=100)
    min_digits: int = Field(1, ge=0, le=20)
    min_symbols: int = Field(1, ge=0, le=20)
    words: int | None = Field(None, ge=3, le=20)
    separator: str = Field("-", max_length=3)
    capitalize: bool = True
    include_number: bool = True


@router.post("/generate")
def generate(request: Request, body: GenerateIn | None = None):
    """Random password (4-128), EFF-wordlist passphrase (3-20 words) or PIN, with entropy + strength."""
    b = (body or GenerateIn()).model_dump()
    return _run(PasswordVaultService.generate, b.pop("mode"), {k: v for k, v in b.items() if v is not None})


class CheckIn(BaseModel):
    password: str = Field(..., max_length=1024)
    user_inputs: list[str] = Field(default_factory=list, max_length=20,
                                   description="words it should not contain: name, site, e-mail ...")
    breach: bool = Field(False, description="also ask Have I Been Pwned (only 5 SHA-1 characters are sent)")


@router.post("/check")
def check(request: Request, body: CheckIn, cu: CurrentUser = Depends(require_session)):
    """Strength meter (zxcvbn: score 0-4, crack times, warning, suggestions) + optional breach check. Nothing is
    stored."""
    inputs = [x[:100] for x in body.user_inputs] + [cu.user["username"], cu.user.get("display_name") or ""]
    return _pv(request).check_password(body.password, inputs, body.breach)


# ================================================================== audit
@router.get("/audit")
def audit(request: Request, cu: CurrentUser = Depends(require_session)):
    """Vault health: 0-100 score + grade, counts (breached, reused, weak, old, http://, duplicates, empty, expired
    cards), strength distribution, reused groups, every issue with the item it belongs to."""
    return _run(_pv(request).audit, cu)


class BreachIn(BaseModel):
    item_ids: list[str] | None = Field(None, max_length=10000)


@router.post("/audit/breaches")
def check_breaches(request: Request, body: BreachIn | None = None, cu: CurrentUser = Depends(require_session)):
    """Check every saved password (or item_ids) against Have I Been Pwned in the background. Poll GET."""
    return _run(_pv(request).start_breach_check, cu, (body or BreachIn()).item_ids)


@router.get("/audit/breaches")
def breach_status(request: Request, cu: CurrentUser = Depends(require_session)):
    return _run(_pv(request).breach_status, cu)


# ================================================================== import / export
class ImportIn(BaseModel):
    format: str = Field("auto", description="auto | " + " | ".join(sorted(FORMATS - {"auto"})))
    content: str | None = Field(None, max_length=10 * 1024 * 1024, description="the file's text")
    path: str | None = Field(None, max_length=4096, description="or: a file on this PC")
    password: str | None = Field(None, max_length=256, description="backup password for .chvault files")
    folder: str | None = Field(None, max_length=60, description="put everything in this folder")
    skip_duplicates: bool = True
    delete_source: bool = Field(False, description="overwrite + delete the file afterwards (path only)")


@router.post("/import")
def import_items(request: Request, body: ImportIn, cu: CurrentUser = Depends(require_session)):
    """Chrome / Edge / Firefox / Bitwarden / LastPass / 1Password / KeePass(XC) CSV, any CSV with
    url,username,password columns, or a Cyber Hub .chvault backup."""
    if body.format not in FORMATS:
        raise HTTPException(422, f"format must be one of: {', '.join(sorted(FORMATS))}")
    return _run(_pv(request).import_items, cu, body.format, body.content, body.path, body.password, body.folder,
                body.skip_duplicates, body.delete_source)


class ExportIn(BaseModel):
    format: Literal["chvault", "csv"] = "chvault"
    master_password: str = Field(..., max_length=256)
    export_password: str | None = Field(None, max_length=256, description="required for chvault")
    confirm: bool = Field(False, description="required for csv (plain text)")
    path: str | None = Field(None, max_length=4096, description="folder or file to write; omit to get content")
    overwrite: bool = False


@router.post("/export")
def export(request: Request, body: ExportIn, cu: CurrentUser = Depends(require_session)):
    """Encrypted .chvault backup (any PC, your backup password) or Bitwarden-style CSV (plain text, 428 until
    confirm=true). Re-asks the master password."""
    return _run(_pv(request).export, cu, body.format, body.master_password, body.export_password, body.confirm,
                body.path, body.overwrite)


# ================================================================== events / graphs
@router.get("/events")
def events(request: Request, cu: CurrentUser = Depends(require_session), after_id: int = Query(0, ge=0),
           severity: str | None = Query(None, pattern="^(" + "|".join(SEVERITIES) + ")$"),
           kind: str | None = Query(None, max_length=40), unacknowledged: bool = False,
           limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
    """Your vault's alerts (poll with after_id): unlock_failed, lockout, breach_found, recovery_used,
    exported_plaintext, master_changed, imported, damaged_items, vault_created / deleted ..."""
    return _pv(request).events(cu, after_id, severity, kind, unacknowledged, limit, offset)


class AckIn(BaseModel):
    ids: list[int] | None = Field(None, max_length=1000)


@router.post("/events/ack")
def ack(request: Request, body: AckIn | None = None, cu: CurrentUser = Depends(require_session)):
    return {"acknowledged": _pv(request).acknowledge(cu, (body or AckIn()).ids)}


@router.delete("/events")
def clear_events(request: Request, cu: CurrentUser = Depends(require_session)):
    return {"deleted": _pv(request).clear_events(cu)}


@router.get("/summary")
def summary(request: Request, cu: CurrentUser = Depends(require_session), days: int = Query(30, ge=1, le=365)):
    """Graphs: health score per day, weak / reused / breached per day, alerts per day by severity, alerts by kind,
    items by type, last audit (works while locked)."""
    return _pv(request).summary(cu, days)
