import secrets
import time
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import redis.asyncio as redis
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import Principal, settings
from app.database import Base, engine, get_db
from app.models import AuditEvent
from app.providers import complete_chat
from app.security import (
    detect_prompt_injection,
    redact_pii,
    violates_output_policy,
)

app = FastAPI(
    title="Enterprise AI Security Gateway",
    description="A privacy-first proxy with PII redaction, prompt-injection checks, and audit controls.",
    version="1.0.0",
)
rate_counters: dict[str, tuple[int, float]] = defaultdict(lambda: (0, 0.0))
redis_client: redis.Redis | None = None


class ChatMessage(BaseModel):
    role: str = Field(pattern=r"^(system|user|assistant)$")
    content: str = Field(min_length=1, max_length=50_000)


class ChatRequest(BaseModel):
    model: str = Field(min_length=1, max_length=120)
    messages: list[ChatMessage] = Field(min_length=1, max_length=100)
    temperature: float | None = Field(default=None, ge=0, le=2)
    max_tokens: int | None = Field(default=None, ge=1, le=16_384)


def authenticate(api_key: str | None = Header(default=None, alias="X-API-Key")) -> Principal:
    if not api_key:
        raise HTTPException(status_code=401, detail="A valid X-API-Key is required")
    for configured_key, principal in settings.api_keys.items():
        if secrets.compare_digest(api_key, configured_key):
            return principal
    raise HTTPException(status_code=401, detail="A valid X-API-Key is required")


async def enforce_rate_limit(principal: Principal) -> None:
    now = time.monotonic()
    if redis_client is not None:
        key = f"rate:{principal.user_id}:{int(time.time() // settings.rate_window_seconds)}"
        async with redis_client.pipeline(transaction=True) as pipe:
            pipe.incr(key)
            pipe.expire(key, settings.rate_window_seconds + 1)
            result = await pipe.execute()
        count = int(result[0])
    else:
        count, expiry = rate_counters[principal.user_id]
        if now >= expiry:
            count, expiry = 0, now + settings.rate_window_seconds
        count += 1
        rate_counters[principal.user_id] = (count, expiry)
    if count > settings.rate_limit:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")


def allowed_model(principal: Principal, model: str) -> bool:
    if principal.role == "admin":
        return True
    return model in {"gpt-4o-mini", "internal-demo"}


def audit(
    db: Session,
    request_id: str,
    principal: Principal,
    model: str,
    action: str,
    reason: str | None = None,
    pii_count: int = 0,
    latency_ms: int = 0,
) -> None:
    db.add(
        AuditEvent(
            request_id=request_id,
            user_id=principal.user_id,
            department=principal.department,
            model=model,
            action=action,
            reason=reason,
            pii_count=pii_count,
            latency_ms=latency_ms,
        )
    )
    db.commit()


@app.on_event("startup")
async def startup() -> None:
    global redis_client
    Base.metadata.create_all(bind=engine)
    if settings.redis_url:
        redis_client = redis.from_url(settings.redis_url, decode_responses=True)
        await redis_client.ping()


@app.on_event("shutdown")
async def shutdown() -> None:
    if redis_client is not None:
        await redis_client.aclose()


@app.get("/", include_in_schema=False)
async def dashboard():
    return FileResponse(Path(__file__).parent / "static" / "index.html")


@app.get("/health")
async def health():
    return {"status": "ok", "service": "enterprise-ai-security-gateway"}


@app.post("/v1/chat/completions")
async def chat_completions(
    body: ChatRequest,
    request: Request,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db),
):
    request_id = str(uuid.uuid4())
    started = time.perf_counter()
    await enforce_rate_limit(principal)

    if not allowed_model(principal, body.model):
        audit(db, request_id, principal, body.model, "blocked", "model_not_allowed")
        raise HTTPException(status_code=403, detail="This role cannot access that model")

    original_messages = [message.model_dump() for message in body.messages]
    full_prompt = "\n".join(message["content"] for message in original_messages)
    if detect_prompt_injection(full_prompt):
        audit(db, request_id, principal, body.model, "blocked", "prompt_injection_detected")
        raise HTTPException(
            status_code=400,
            detail={"message": "Prompt blocked by security policy", "request_id": request_id},
        )

    redactions = []
    safe_messages = []
    for message in original_messages:
        result = redact_pii(message["content"])
        redactions.append(result)
        safe_messages.append({**message, "content": result.text})

    upstream_payload = body.model_dump(exclude_none=True)
    upstream_payload["messages"] = safe_messages
    try:
        response = await complete_chat(upstream_payload)
    except httpx.HTTPStatusError as exc:
        audit(
            db, request_id, principal, body.model, "error",
            f"upstream_http_{exc.response.status_code}",
            sum(result.count for result in redactions),
            int((time.perf_counter() - started) * 1000),
        )
        raise HTTPException(status_code=502, detail="The model provider returned an error") from exc
    except httpx.RequestError as exc:
        audit(
            db, request_id, principal, body.model, "error", "upstream_unavailable",
            sum(result.count for result in redactions),
            int((time.perf_counter() - started) * 1000),
        )
        raise HTTPException(status_code=502, detail="The model provider is unavailable") from exc

    choices = response.get("choices", [])
    for choice in choices:
        content = choice.get("message", {}).get("content")
        if isinstance(content, str):
            if violates_output_policy(content):
                audit(
                    db, request_id, principal, body.model, "blocked",
                    "response_policy_violation",
                    sum(result.count for result in redactions),
                    int((time.perf_counter() - started) * 1000),
                )
                raise HTTPException(
                    status_code=502,
                    detail="Model response blocked by corporate safety policy",
                )
            for result in redactions:
                content = result.restore(content)
            choice["message"]["content"] = content

    audit(
        db, request_id, principal, body.model, "allowed", None,
        sum(result.count for result in redactions),
        int((time.perf_counter() - started) * 1000),
    )
    response["gateway_request_id"] = request_id
    return response


@app.get("/api/audit")
async def get_audit(
    limit: int = 50,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db),
):
    if principal.role != "admin":
        raise HTTPException(status_code=403, detail="Administrator role required")
    if not 1 <= limit <= 200:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 200")
    events = db.scalars(
        select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit)
    ).all()
    return [
        {
            "request_id": event.request_id,
            "user_id": event.user_id,
            "department": event.department,
            "model": event.model,
            "action": event.action,
            "reason": event.reason,
            "pii_count": event.pii_count,
            "latency_ms": event.latency_ms,
            "created_at": event.created_at.isoformat(),
        }
        for event in events
    ]


@app.get("/api/metrics")
async def get_metrics(
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db),
):
    if principal.role != "admin":
        raise HTTPException(status_code=403, detail="Administrator role required")
    since = datetime.now(timezone.utc) - timedelta(days=1)
    rows = db.execute(
        select(AuditEvent.action, func.count(AuditEvent.id))
        .where(AuditEvent.created_at >= since)
        .group_by(AuditEvent.action)
    ).all()
    by_action = {action: count for action, count in rows}
    total = sum(by_action.values())
    return {
        "window": "24h",
        "total_requests": total,
        "allowed": by_action.get("allowed", 0),
        "blocked": by_action.get("blocked", 0),
        "errors": by_action.get("error", 0),
    }
