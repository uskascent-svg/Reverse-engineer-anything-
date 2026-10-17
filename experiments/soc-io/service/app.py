"""SOC-IO authenticated multi-tenant case API.

Experimental service foundation. Requires PostgreSQL, OIDC JWTs signed with RS256,
and pre-provisioned socio_users/socio_memberships rows. No response actions exist.
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Annotated, Any
from urllib.parse import urlparse
from uuid import UUID

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient
from pydantic import BaseModel, ConfigDict, Field
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

ROLES = {"viewer", "analyst", "incident_lead", "administrator"}
CASE_STATUSES = {"open", "investigating", "contained", "resolved", "closed"}
SEVERITIES = {"critical", "high", "medium", "low", "info"}
bearer = HTTPBearer(auto_error=False)


def require_role(actual: str, allowed: set[str]) -> None:
    if actual not in ROLES or actual not in allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")


def oidc_settings() -> tuple[str, str, str]:
    issuer = os.getenv("SOCIO_OIDC_ISSUER", "").strip()
    audience = os.getenv("SOCIO_OIDC_AUDIENCE", "").strip()
    jwks_url = os.getenv("SOCIO_OIDC_JWKS_URL", "").strip()
    if not issuer or not audience or not jwks_url:
        raise RuntimeError(
            "Set SOCIO_OIDC_ISSUER, SOCIO_OIDC_AUDIENCE, and SOCIO_OIDC_JWKS_URL"
        )
    issuer_url = urlparse(issuer)
    jwks = urlparse(jwks_url)
    if (
        issuer_url.scheme != "https"
        or not issuer_url.hostname
        or issuer_url.username
        or issuer_url.password
        or issuer_url.fragment
    ):
        raise RuntimeError("SOCIO_OIDC_ISSUER must be an absolute HTTPS issuer URL")
    if (
        jwks.scheme != "https"
        or not jwks.hostname
        or jwks.username
        or jwks.password
        or jwks.fragment
    ):
        raise RuntimeError("SOCIO_OIDC_JWKS_URL must be an absolute HTTPS URL")
    return issuer, audience, jwks_url


def verify_token(token: str) -> dict[str, Any]:
    issuer, audience, jwks_url = oidc_settings()
    client = PyJWKClient(jwks_url, cache_keys=True, lifespan=300)
    try:
        signing_key = client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=audience,
            issuer=issuer,
            options={"require": ["exp", "iat", "sub", "iss", "aud"]},
            leeway=30,
        )
    except Exception as exc:
        # Do not return token, JWKS response, or provider internals to callers.
        raise HTTPException(status_code=401, detail="Invalid or expired bearer token") from exc
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise HTTPException(status_code=401, detail="Token subject is missing")
    return claims


@dataclass
class Principal:
    conn: Any
    tenant_id: UUID
    user_id: UUID
    issuer: str
    subject: str
    role: str
    request_id: str


class CaseCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=1, max_length=500)
    summary: str = Field(default="", max_length=20000)
    severity: str = "medium"


class CaseUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str | None = Field(default=None, min_length=1, max_length=500)
    summary: str | None = Field(default=None, max_length=20000)
    status: str | None = None
    severity: str | None = None
    assigned_to: UUID | None = None


class NoteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    body: str = Field(min_length=1, max_length=50000)


def _audit(
    principal: Principal,
    action: str,
    target_type: str,
    target_id: str,
    outcome: str = "success",
    metadata: dict[str, Any] | None = None,
) -> None:
    principal.conn.execute(
        """
        INSERT INTO socio_audit_events
          (tenant_id, actor_user_id, action, target_type, target_id, request_id, outcome, metadata)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            principal.tenant_id, principal.user_id, action, target_type,
            target_id[:512], principal.request_id, outcome, Jsonb(metadata or {}),
        ),
    )


def _case_or_404(principal: Principal, case_id: UUID) -> dict[str, Any]:
    row = principal.conn.execute(
        """
        SELECT id, tenant_id, title, summary, status, severity, assigned_to,
               created_by, version, created_at, updated_at
        FROM socio_cases WHERE id = %s
        """,
        (case_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return row


async def current_principal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    tenant_header: Annotated[UUID | None, Header(alias="X-SOC-IO-Tenant")] = None,
    request_id: Annotated[str | None, Header(alias="X-Request-ID")] = None,
):
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Bearer token required",
                            headers={"WWW-Authenticate": "Bearer"})
    if tenant_header is None:
        raise HTTPException(status_code=400, detail="X-SOC-IO-Tenant header is required")
    claims = verify_token(credentials.credentials)
    issuer, _, _ = oidc_settings()
    pool: ConnectionPool = request.app.state.pool
    # A single transaction scopes tenant and actor settings. The client-supplied
    # tenant is only a selector: membership is independently verified below.
    with pool.connection() as conn:
        with conn.transaction():
            conn.row_factory = dict_row
            conn.execute(
                "SELECT set_config('soc_io.tenant_id', %s, true)",
                (str(tenant_header),),
            )
            membership = conn.execute(
                """
                SELECT u.id AS user_id, m.role
                FROM socio_memberships m
                JOIN socio_users u ON u.id = m.user_id
                WHERE m.tenant_id = %s AND u.issuer = %s AND u.subject = %s
                """,
                (tenant_header, issuer, claims["sub"]),
            ).fetchone()
            if membership is None or membership["role"] not in ROLES:
                raise HTTPException(status_code=403, detail="No membership in requested tenant")
            user_id = membership["user_id"]
            conn.execute(
                "SELECT set_config('soc_io.actor_user_id', %s, true)",
                (str(user_id),),
            )
            principal = Principal(
                conn=conn,
                tenant_id=tenant_header,
                user_id=user_id,
                issuer=issuer,
                subject=claims["sub"],
                role=membership["role"],
                request_id=(request_id or "")[:256],
            )
            yield principal


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Fail closed at startup instead of returning 500s for every auth request.
    oidc_settings()
    dsn = os.getenv("DATABASE_URL", "").strip()
    if not dsn:
        raise RuntimeError("DATABASE_URL must be configured before starting SOC-IO service")
    pool = ConnectionPool(conninfo=dsn, min_size=1, max_size=10, open=False,
                          kwargs={"row_factory": dict_row})
    pool.open(wait=True, timeout=10)
    app.state.pool = pool
    try:
        yield
    finally:
        pool.close()


app = FastAPI(
    title="SOC-IO Case API",
    version="0.1.0-experimental",
    description=(
        "Experimental authenticated multi-tenant case API. "
        "No forecasting or response-action endpoints are exposed."
    ),
    lifespan=lifespan,
)


@app.get("/health")
def health():
    return {"status": "ok", "service": "soc-io-case-api", "mode": "experimental"}


@app.get("/api/me")
def who_am_i(principal: Annotated[Principal, Depends(current_principal)]):
    return {
        "user_id": str(principal.user_id),
        "tenant_id": str(principal.tenant_id),
        "role": principal.role,
        "issuer": principal.issuer,
        "subject": principal.subject,
    }


@app.post("/api/cases", status_code=201)
def create_case(body: CaseCreate, principal: Annotated[Principal, Depends(current_principal)]):
    require_role(principal.role, {"analyst", "incident_lead", "administrator"})
    title = body.title.strip()
    if not title:
        raise HTTPException(status_code=422, detail="Title cannot be blank")
    if body.severity not in SEVERITIES:
        raise HTTPException(status_code=422, detail="Invalid severity")
    row = principal.conn.execute(
        """
        INSERT INTO socio_cases
          (tenant_id, title, summary, severity, created_by)
        VALUES (%s, %s, %s, %s, %s)
        RETURNING id, tenant_id, title, summary, status, severity, assigned_to,
                  created_by, version, created_at, updated_at
        """,
        (principal.tenant_id, title, body.summary, body.severity, principal.user_id),
    ).fetchone()
    principal.conn.execute(
        """
        INSERT INTO socio_case_events (tenant_id, case_id, actor_user_id, event_type, event_data)
        VALUES (%s, %s, %s, 'case_created', %s)
        """,
        (principal.tenant_id, row["id"], principal.user_id,
         Jsonb({"title": row["title"], "severity": row["severity"]})),
    )
    _audit(principal, "case.create", "case", str(row["id"]),
           metadata={"severity": row["severity"]})
    return row


@app.get("/api/cases")
def list_cases(
    principal: Annotated[Principal, Depends(current_principal)],
    limit: int = 50,
    offset: int = 0,
    case_status: str | None = None,
):
    if not 1 <= limit <= 100 or offset < 0:
        raise HTTPException(status_code=422, detail="limit must be 1..100 and offset non-negative")
    if case_status is not None and case_status not in CASE_STATUSES:
        raise HTTPException(status_code=422, detail="Invalid status")
    if case_status:
        rows = principal.conn.execute(
            """
            SELECT id, tenant_id, title, summary, status, severity, assigned_to,
                   created_by, version, created_at, updated_at
            FROM socio_cases WHERE status = %s
            ORDER BY updated_at DESC LIMIT %s OFFSET %s
            """, (case_status, limit, offset),
        ).fetchall()
    else:
        rows = principal.conn.execute(
            """
            SELECT id, tenant_id, title, summary, status, severity, assigned_to,
                   created_by, version, created_at, updated_at
            FROM socio_cases ORDER BY updated_at DESC LIMIT %s OFFSET %s
            """, (limit, offset),
        ).fetchall()
    return {"items": rows, "limit": limit, "offset": offset}


@app.get("/api/cases/{case_id}")
def get_case(case_id: UUID, principal: Annotated[Principal, Depends(current_principal)]):
    return _case_or_404(principal, case_id)


@app.patch("/api/cases/{case_id}")
def update_case(
    case_id: UUID,
    body: CaseUpdate,
    principal: Annotated[Principal, Depends(current_principal)],
):
    require_role(principal.role, {"analyst", "incident_lead", "administrator"})
    existing = _case_or_404(principal, case_id)
    updates = body.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=422, detail="At least one field is required")
    for required_field in ("title", "summary", "status", "severity"):
        if required_field in updates and updates[required_field] is None:
            raise HTTPException(status_code=422, detail=f"{required_field} cannot be null")
    if "title" in updates:
        updates["title"] = updates["title"].strip()
        if not updates["title"]:
            raise HTTPException(status_code=422, detail="Title cannot be blank")
    if "status" in updates and updates["status"] not in CASE_STATUSES:
        raise HTTPException(status_code=422, detail="Invalid status")
    if "severity" in updates and updates["severity"] not in SEVERITIES:
        raise HTTPException(status_code=422, detail="Invalid severity")
    if "status" in updates and updates["status"] in {"contained", "resolved", "closed"} and principal.role == "analyst":
        raise HTTPException(status_code=403, detail="Incident lead approval is required for terminal case states")
    if "assigned_to" in updates and principal.role not in {"incident_lead", "administrator"}:
        raise HTTPException(status_code=403, detail="Only incident leads/admins can assign cases")
    if "assigned_to" in updates and updates["assigned_to"] is not None:
        assigned = principal.conn.execute(
            """
            SELECT 1 FROM socio_memberships
            WHERE tenant_id = %s AND user_id = %s
            """, (principal.tenant_id, updates["assigned_to"]),
        ).fetchone()
        if assigned is None:
            raise HTTPException(status_code=422, detail="Assignee is not a member of this tenant")
    allowed = {"title", "summary", "status", "severity", "assigned_to"}
    assignments = [key for key in updates if key in allowed]
    # Column names come only from the fixed allow-list above; values are bound.
    set_clause = ", ".join(f"{key} = %s" for key in assignments)
    values = [updates[key] for key in assignments]
    values.extend([existing["version"] + 1, case_id, existing["version"]])
    row = principal.conn.execute(
        f"""
        UPDATE socio_cases SET {set_clause}, version = %s, updated_at = now()
        WHERE id = %s AND version = %s
        RETURNING id, tenant_id, title, summary, status, severity, assigned_to,
                  created_by, version, created_at, updated_at
        """,
        tuple(values),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=409, detail="Case changed concurrently; reload and retry")
    principal.conn.execute(
        """
        INSERT INTO socio_case_events (tenant_id, case_id, actor_user_id, event_type, event_data)
        VALUES (%s, %s, %s, 'case_updated', %s)
        """,
        (principal.tenant_id, case_id, principal.user_id,
         Jsonb({"changed_fields": assignments, "version": row["version"]})),
    )
    _audit(principal, "case.update", "case", str(case_id),
           metadata={"changed_fields": assignments, "version": row["version"]})
    return row


@app.get("/api/cases/{case_id}/notes")
def list_notes(case_id: UUID, principal: Annotated[Principal, Depends(current_principal)]):
    _case_or_404(principal, case_id)
    return principal.conn.execute(
        """
        SELECT id, case_id, author_user_id, body, created_at
        FROM socio_case_notes WHERE case_id = %s ORDER BY created_at ASC
        """, (case_id,),
    ).fetchall()


@app.post("/api/cases/{case_id}/notes", status_code=201)
def add_note(
    case_id: UUID,
    body: NoteCreate,
    principal: Annotated[Principal, Depends(current_principal)],
):
    require_role(principal.role, {"analyst", "incident_lead", "administrator"})
    _case_or_404(principal, case_id)
    note = principal.conn.execute(
        """
        INSERT INTO socio_case_notes (tenant_id, case_id, author_user_id, body)
        VALUES (%s, %s, %s, %s)
        RETURNING id, case_id, author_user_id, body, created_at
        """, (principal.tenant_id, case_id, principal.user_id, body.body.strip()),
    ).fetchone()
    principal.conn.execute(
        """
        INSERT INTO socio_case_events (tenant_id, case_id, actor_user_id, event_type, event_data)
        VALUES (%s, %s, %s, 'note_added', %s)
        """, (principal.tenant_id, case_id, principal.user_id,
              Jsonb({"note_id": str(note["id"])})),
    )
    _audit(principal, "case.note.create", "case", str(case_id),
           metadata={"note_id": str(note["id"])})
    return note


@app.get("/api/cases/{case_id}/events")
def list_case_events(
    case_id: UUID,
    principal: Annotated[Principal, Depends(current_principal)],
    limit: int = 100,
):
    _case_or_404(principal, case_id)
    if not 1 <= limit <= 500:
        raise HTTPException(status_code=422, detail="limit must be 1..500")
    return principal.conn.execute(
        """
        SELECT id, case_id, actor_user_id, event_type, event_data, created_at
        FROM socio_case_events WHERE case_id = %s ORDER BY id DESC LIMIT %s
        """, (case_id, limit),
    ).fetchall()


@app.get("/api/audit")
def list_audit(
    principal: Annotated[Principal, Depends(current_principal)],
    limit: int = 100,
):
    require_role(principal.role, {"incident_lead", "administrator"})
    if not 1 <= limit <= 500:
        raise HTTPException(status_code=422, detail="limit must be 1..500")
    return principal.conn.execute(
        """
        SELECT id, actor_user_id, action, target_type, target_id, request_id,
               outcome, metadata, created_at
        FROM socio_audit_events ORDER BY id DESC LIMIT %s
        """, (limit,),
    ).fetchall()
