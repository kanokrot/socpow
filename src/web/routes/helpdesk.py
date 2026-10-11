"""Authenticated feedback submission and admin-managed helpdesk FAQ."""

from __future__ import annotations

import importlib.util
import os
import sqlite3
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..auth import get_current_user, require_role


PROJECT_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_PATH = PROJECT_ROOT / "src" / "db" / "migrations" / "015_add_helpdesk.py"
router = APIRouter()


def _auth_db_path() -> Path:
    return Path(os.getenv("AUTH_DB_PATH", "src/db/auth.db"))


def _upgrade(connection: sqlite3.Connection) -> None:
    spec = importlib.util.spec_from_file_location(
        "_helpdesk_migration_015", MIGRATION_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Helpdesk migration is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.upgrade(connection)


def _connect() -> sqlite3.Connection:
    path = _auth_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path), timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


class FeedbackCreate(BaseModel):
    type: Literal["wrong_verdict", "bug", "suggestion"]
    reference: str | None = Field(default=None, max_length=200)
    message: str = Field(min_length=1, max_length=2000)

    @field_validator("message")
    def message_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Message must not be empty")
        return value

    model_config = ConfigDict(extra="forbid")


class FeedbackUpdate(BaseModel):
    status: Literal["new", "reviewed", "resolved"] | None = None
    admin_note: str | None = Field(default=None, max_length=2000)

    model_config = ConfigDict(extra="forbid")


class FAQCreate(BaseModel):
    question: str = Field(min_length=1, max_length=300)
    answer: str = Field(min_length=1, max_length=4000)
    sort_order: int = 0
    is_published: int = Field(default=1, ge=0, le=1)

    model_config = ConfigDict(extra="forbid")


class FAQUpdate(BaseModel):
    question: str | None = Field(default=None, min_length=1, max_length=300)
    answer: str | None = Field(default=None, min_length=1, max_length=4000)
    sort_order: int | None = None
    is_published: int | None = Field(default=None, ge=0, le=1)

    model_config = ConfigDict(extra="forbid")


def _rows(connection: sqlite3.Connection, query: str, values: tuple = ()) -> list[dict]:
    return [dict(row) for row in connection.execute(query, values).fetchall()]


@router.post("/feedback", status_code=status.HTTP_201_CREATED)
def submit_feedback(
    payload: FeedbackCreate,
    current_user: dict = Depends(get_current_user),
) -> dict:
    with _connect() as connection:
        _upgrade(connection)
        connection.execute("BEGIN IMMEDIATE")
        recent_count = connection.execute(
            "SELECT COUNT(*) FROM helpdesk_feedback "
            "WHERE submitter_id = ? AND created_at >= "
            "strftime('%Y-%m-%d %H:%M:%S', 'now', '-1 hour')",
            (int(current_user["id"]),),
        ).fetchone()[0]
        if recent_count >= 20:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Feedback limit reached: maximum 20 submissions per hour.",
            )
        cursor = connection.execute(
            "INSERT INTO helpdesk_feedback (submitter_id, type, reference, message) "
            "VALUES (?, ?, ?, ?)",
            (
                int(current_user["id"]),
                payload.type,
                payload.reference,
                payload.message,
            ),
        )
        feedback_id = int(cursor.lastrowid)
        connection.commit()
    return {"id": feedback_id, "status": "new"}


@router.get("/faq")
def list_published_faq(
    current_user: dict = Depends(get_current_user),
) -> dict:
    with _connect() as connection:
        _upgrade(connection)
        items = _rows(
            connection,
            "SELECT id, question, answer, sort_order, created_at, updated_at "
            "FROM helpdesk_faq WHERE is_published = 1 "
            "ORDER BY sort_order ASC, id ASC",
        )
    return {"items": items}


@router.get("/admin/feedback")
def list_feedback(
    status: str | None = None,
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _admin: dict = Depends(require_role("admin")),
) -> dict:
    if status is not None and status not in {
        "new", "reviewed", "resolved"
    }:
        raise HTTPException(status_code=422, detail="Invalid feedback status")
    query = (
        "SELECT feedback.id, feedback.submitter_id, submitter.username AS submitter_username, "
        "feedback.type, feedback.reference, feedback.message, feedback.status, "
        "feedback.admin_note, feedback.created_at, feedback.updated_at "
        "FROM helpdesk_feedback AS feedback "
        "LEFT JOIN users AS submitter ON submitter.id = feedback.submitter_id"
    )
    values: tuple = ()
    if status is not None:
        query += " WHERE status = ?"
        values = (status,)
    query += " ORDER BY feedback.created_at DESC, feedback.id DESC LIMIT ? OFFSET ?"
    values += (limit, offset)
    with _connect() as connection:
        _upgrade(connection)
        items = _rows(connection, query, values)
    return {"items": items}


@router.patch("/admin/feedback/{feedback_id}")
def update_feedback(
    feedback_id: int,
    payload: FeedbackUpdate,
    _admin: dict = Depends(require_role("admin")),
) -> dict:
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=422, detail="No feedback fields to update")
    if "status" in changes and changes["status"] is None:
        raise HTTPException(status_code=422, detail="Status cannot be null")
    assignments = [f"{field} = ?" for field in changes]
    values = list(changes.values())
    assignments.append("updated_at = CURRENT_TIMESTAMP")
    with _connect() as connection:
        _upgrade(connection)
        cursor = connection.execute(
            f"UPDATE helpdesk_feedback SET {', '.join(assignments)} WHERE id = ?",
            (*values, feedback_id),
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Feedback not found")
        connection.commit()
        row = connection.execute(
            "SELECT id, submitter_id, type, reference, message, status, admin_note, "
            "created_at, updated_at FROM helpdesk_feedback WHERE id = ?",
            (feedback_id,),
        ).fetchone()
    return dict(row)


@router.get("/admin/faq")
def list_all_faq(
    _admin: dict = Depends(require_role("admin")),
) -> dict:
    with _connect() as connection:
        _upgrade(connection)
        items = _rows(
            connection,
            "SELECT id, question, answer, sort_order, is_published, created_at, "
            "updated_at, updated_by FROM helpdesk_faq "
            "ORDER BY sort_order ASC, id ASC",
        )
    return {"items": items}


@router.post("/admin/faq", status_code=status.HTTP_201_CREATED)
def create_faq(
    payload: FAQCreate,
    admin: dict = Depends(require_role("admin")),
) -> dict:
    with _connect() as connection:
        _upgrade(connection)
        cursor = connection.execute(
            "INSERT INTO helpdesk_faq "
            "(question, answer, sort_order, is_published, updated_by) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                payload.question,
                payload.answer,
                payload.sort_order,
                payload.is_published,
                int(admin["id"]),
            ),
        )
        faq_id = int(cursor.lastrowid)
        connection.commit()
        row = connection.execute(
            "SELECT id, question, answer, sort_order, is_published, created_at, "
            "updated_at, updated_by FROM helpdesk_faq WHERE id = ?",
            (faq_id,),
        ).fetchone()
    return dict(row)


@router.patch("/admin/faq/{faq_id}")
def update_faq(
    faq_id: int,
    payload: FAQUpdate,
    admin: dict = Depends(require_role("admin")),
) -> dict:
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=422, detail="No FAQ fields to update")
    if any(value is None for value in changes.values()):
        raise HTTPException(status_code=422, detail="FAQ fields cannot be null")
    assignments = [f"{field} = ?" for field in changes]
    values = list(changes.values())
    assignments.extend(("updated_by = ?", "updated_at = CURRENT_TIMESTAMP"))
    values.extend((int(admin["id"]), faq_id))
    with _connect() as connection:
        _upgrade(connection)
        cursor = connection.execute(
            f"UPDATE helpdesk_faq SET {', '.join(assignments)} WHERE id = ?",
            tuple(values),
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="FAQ entry not found")
        connection.commit()
        row = connection.execute(
            "SELECT id, question, answer, sort_order, is_published, created_at, "
            "updated_at, updated_by FROM helpdesk_faq WHERE id = ?",
            (faq_id,),
        ).fetchone()
    return dict(row)


@router.delete("/admin/faq/{faq_id}")
def delete_faq(
    faq_id: int,
    _admin: dict = Depends(require_role("admin")),
) -> dict:
    with _connect() as connection:
        _upgrade(connection)
        cursor = connection.execute(
            "DELETE FROM helpdesk_faq WHERE id = ?", (faq_id,)
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="FAQ entry not found")
        connection.commit()
    return {"deleted": True}
