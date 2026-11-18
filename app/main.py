"""FastAPI application: receive SAO alert webhooks, forward them to Splunk HEC."""

from __future__ import annotations

import hmac
import json
import logging
import time
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import BackgroundTasks, FastAPI, Header, Request, Response
from fastapi.responses import JSONResponse

from app import __version__
from app.config import Settings, get_settings
from app.hec import HECClient
from app.transform import flatten, to_hec_envelope

logger = logging.getLogger("sao_hec_bridge")


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings: Settings = get_settings()
    _configure_logging(settings.log_level)

    problems = settings.validate_startup()
    if problems:
        for problem in problems:
            logger.critical("Configuration error: %s", problem)
        raise RuntimeError("Invalid configuration: " + "; ".join(problems))

    if not settings.webhook_token:
        logger.warning(
            "ALLOW_INSECURE is set and WEBHOOK_TOKEN is empty: this endpoint "
            "accepts UNAUTHENTICATED requests. Do not run this way in production."
        )
    if not settings.hec_verify_tls:
        logger.warning("HEC TLS verification is DISABLED (HEC_VERIFY_TLS=false).")

    client = httpx.AsyncClient(verify=settings.hec_verify_tls)
    app.state.settings = settings
    app.state.hec = HECClient(settings, client)
    logger.info(
        "Ready. Forwarding to %s (index=%s sourcetype=%s)",
        settings.hec_event_url,
        settings.hec_index,
        settings.hec_sourcetype,
    )
    try:
        yield
    finally:
        await client.aclose()


app = FastAPI(
    title="SAO -> Splunk HEC webhook bridge",
    version=__version__,
    lifespan=lifespan,
)


def _authorized(settings: Settings, authorization: str | None) -> bool:
    """Constant-time check of the `Authorization: Bearer <token>` header."""
    if not settings.webhook_token:
        # Only reachable when ALLOW_INSECURE=true (enforced at startup).
        return True
    if not authorization:
        return False
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer":
        return False
    return hmac.compare_digest(token.strip(), settings.webhook_token)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    """Liveness probe backing the container healthcheck."""
    return {"status": "ok", "version": __version__}


@app.post("/webhook/sao")
async def receive_sao_alert(
    request: Request,
    background_tasks: BackgroundTasks,
    authorization: str | None = Header(default=None),
) -> Response:
    received_at = time.time()
    settings: Settings = request.app.state.settings

    if not _authorized(settings, authorization):
        logger.warning("Rejected unauthorized webhook request from %s", request.client)
        return JSONResponse(
            status_code=401,
            content={"status": "unauthorized"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    raw = await request.body()
    try:
        payload: Any = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        logger.warning("Rejected non-JSON body: %s", exc)
        return JSONResponse(
            status_code=400, content={"status": "error", "detail": "body is not valid JSON"}
        )

    if not isinstance(payload, dict):
        logger.warning("Rejected JSON body of type %s (expected object)", type(payload).__name__)
        return JSONResponse(
            status_code=400,
            content={"status": "error", "detail": "body must be a JSON object"},
        )

    flat = flatten(payload, settings)
    envelope = to_hec_envelope(flat, settings, received_at)

    event_id = flat.get("event_id")
    dedup_key = flat.get("dedup_key")
    context = f"event_id={event_id} dedup_key={dedup_key}"
    logger.info(
        "Accepted %s alert=%r status=%r (%s)",
        flat.get("event_type") or "event",
        flat.get("alert_name"),
        flat.get("alert_status"),
        context,
    )
    # Full inbound payload, single line so log parsers see one record.
    logger.info(
        "SAO payload (%s): %s",
        context,
        json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str),
    )

    hec: HECClient = request.app.state.hec
    background_tasks.add_task(hec.send, envelope, context=context)

    # Ack before the HEC round trip: keeps SAO's webhook badge Active through
    # Splunk blips. Trade-off: in-flight events are lost if we are killed
    # mid-retry. See README.
    return JSONResponse(
        status_code=200,
        content={"status": "accepted", "event_id": event_id, "dedup_key": dedup_key},
    )
