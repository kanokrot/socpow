"""Authenticated, owner-scoped API key management for enrichment lookups."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from ..auth import get_current_user
from ..user_api_keys import (
    ALLOWED_SOURCES,
    DISABLED_REASON,
    UserApiKeyCipher,
    UserApiKeyEncryptionUnavailable,
    UserApiKeyStore,
)


router = APIRouter()


def _audit(request: Request, current_user: dict, source: str, action: str) -> None:
    """Write key-free audit metadata through the shared audit store."""
    store = getattr(request.app.state, "agent_store", None)
    if store is None or not hasattr(store, "add_audit_entry"):
        return
    try:
        user_id = int(current_user["id"])
        store.add_audit_entry(
            session_id=None,
            action=f"user_api_key_{action}",
            action_type="user_api_key_management",
            actor=f"user:{user_id}",
            actor_role=current_user.get("role", ""),
            target_user_id=user_id,
            resource_type="user_api_key",
            resource_id=source,
            after_state={"user_id": user_id, "source": source, "action": action},
        )
    except Exception:
        # Deliberately do not log audit exceptions or key-bearing request data.
        return


def _reject_admin(current_user: dict) -> None:
    if current_user.get("role") == "admin":
        raise HTTPException(status_code=403, detail="Personal API keys are unavailable to administrators")


def _validate_source(source: str) -> None:
    if source not in ALLOWED_SOURCES:
        raise HTTPException(status_code=400, detail="Unsupported intelligence source")


@router.get("/intel-keys")
def list_intel_keys(current_user: dict = Depends(get_current_user)) -> dict:
    _reject_admin(current_user)
    try:
        UserApiKeyCipher()
    except UserApiKeyEncryptionUnavailable:
        return {"enabled": False, "reason": DISABLED_REASON}
    store = UserApiKeyStore()
    rows = store.list_metadata(int(current_user["id"]))
    user_keys = store.keys_for_lookup(int(current_user["id"])) if any(row["configured"] for row in rows) else {}
    for row in rows:
        key = user_keys.get(row["source"])
        row["masked_suffix"] = "••••" + key[-4:] if key else None
    return {
        "enabled": True,
        "keys": rows,
    }


@router.put("/intel-keys/{source}")
async def save_intel_key(
    source: str,
    request: Request,
    current_user: dict = Depends(get_current_user),
) -> dict:
    _reject_admin(current_user)
    _validate_source(source)
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Expected JSON body") from None
    if not isinstance(payload, dict) or set(payload) != {"api_key"}:
        raise HTTPException(status_code=400, detail="Body must contain only api_key")
    api_key = payload.get("api_key")
    if not isinstance(api_key, str) or not api_key.strip() or len(api_key) > 4096:
        raise HTTPException(status_code=400, detail="Invalid API key")
    try:
        UserApiKeyStore().save(int(current_user["id"]), source, api_key)
    except UserApiKeyEncryptionUnavailable:
        raise HTTPException(
            status_code=503, detail="API key storage is unavailable"
        ) from None
    _audit(request, current_user, source, "set")
    return {"source": source, "configured": True}


@router.delete("/intel-keys/{source}", status_code=status.HTTP_204_NO_CONTENT)
def delete_intel_key(
    source: str,
    request: Request,
    current_user: dict = Depends(get_current_user),
) -> Response:
    _reject_admin(current_user)
    _validate_source(source)
    try:
        UserApiKeyCipher()
    except UserApiKeyEncryptionUnavailable:
        raise HTTPException(
            status_code=503, detail="API key storage is unavailable"
        ) from None
    deleted = UserApiKeyStore().delete(int(current_user["id"]), source)
    if deleted:
        _audit(request, current_user, source, "delete")
    return Response(status_code=status.HTTP_204_NO_CONTENT)
