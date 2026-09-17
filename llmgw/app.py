"""wormbench llmgw — the LLM metering gateway (SPEC-v0.2 §6).

The ONLY path from any worm instance to ollama. Drop-in ollama API shape on
port 11434, except every /api/generate costs credits:

  1. auth: caller presents its instance token (X-Instance-Token) + id
     (X-Instance-Id) — the same credentials it uses against the judge.
  2. debit: POST judge /wallet/debit {instance_id, amount: COST_LLM_CALL}.
     Insufficient funds -> HTTP 402, ollama is NEVER called (SPEC §4.2).
  3. forward: POST ollama /api/generate (stream=false enforced, v0.1 options
     discipline) and relay the response.

/api/tags (model presence) and /health are free — the worm's readiness probe
must not cost money (SPEC §5.2 wait_for_ollama).

Concurrency (scan finding: "a one-credit request can monopolize the gateway"):
all outbound calls use an ASYNC client — a slow generation must not block the
event loop, or concurrent instances (root + children) serialize behind it.
Generation inputs are CLAMPED server-side (num_predict <= 512, prompt size)
so one credit can never buy unbounded model time.
"""

import os

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

JUDGE_URL = os.environ.get("JUDGE_URL", "http://judge:8000").rstrip("/")
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://ollama:11434").rstrip("/")
COST_LLM_CALL = int(os.environ.get("COST_LLM_CALL", "1"))

MAX_NUM_PREDICT = 512
MAX_PROMPT_CHARS = 32_000
MAX_BODY_BYTES = 128_000

app = FastAPI()
_client = httpx.AsyncClient(timeout=600.0)


@app.get("/health")
async def health():
    """Readiness for the worm's wait_for_ollama: is ollama up + model pulled?"""
    try:
        r = await _client.get(OLLAMA_HOST + "/api/tags", timeout=10.0)
        r.raise_for_status()
        return {"ok": True, "models": [m.get("name") for m in r.json().get("models", [])]}
    except Exception as exc:
        return JSONResponse(status_code=503, content={"ok": False, "detail": str(exc)})


@app.get("/api/tags")
async def tags():
    """Free passthrough so tools.ollama_ready works unchanged against llmgw."""
    r = await _client.get(OLLAMA_HOST + "/api/tags", timeout=10.0)
    return r.json()


async def _debit(instance_id: str, token: str) -> tuple[bool, int]:
    """Ask the judge to debit COST_LLM_CALL. Returns (ok, balance)."""
    r = await _client.post(
        JUDGE_URL + "/wallet/debit",
        json={"instance_id": instance_id, "amount": COST_LLM_CALL},
        headers={"X-Judge-Token": token},
        timeout=15.0,
    )
    if r.status_code == 402:
        return False, r.json().get("balance", 0)
    r.raise_for_status()
    body = r.json()
    return bool(body.get("ok")), int(body.get("balance", 0))


@app.post("/api/generate")
async def generate(request: Request):
    token = request.headers.get("x-instance-token", "")
    instance_id = request.headers.get("x-instance-id", "worm:c0")
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"detail": "invalid JSON"})
    if not isinstance(payload, dict):
        return JSONResponse(status_code=400, content={"detail": "invalid payload"})

    # Clamp generation inputs server-side: one credit buys at most the
    # documented contract, never unbounded model time (scan finding).
    prompt = payload.get("prompt")
    if not isinstance(prompt, str) or len(prompt) > MAX_PROMPT_CHARS:
        return JSONResponse(status_code=400, content={"detail": "prompt missing or too large"})
    payload["stream"] = False
    opts = payload.setdefault("options", {})
    if not isinstance(opts, dict):
        return JSONResponse(status_code=400, content={"detail": "invalid options"})
    try:
        opts["num_predict"] = min(max(int(opts.get("num_predict", 512)), 1), MAX_NUM_PREDICT)
        opts["temperature"] = min(max(float(opts.get("temperature", 0.4)), 0.0), 2.0)
    except (TypeError, ValueError):
        return JSONResponse(status_code=400, content={"detail": "invalid options"})

    ok, balance = await _debit(instance_id, token)
    if not ok:
        # SPEC §4.2/§5.2: the agent's death signal. ollama is never called.
        return JSONResponse(
            status_code=402,
            content={"detail": "insufficient credits", "balance": balance},
        )

    try:
        r = await _client.post(OLLAMA_HOST + "/api/generate", json=payload)
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        # Forwarding failure: the debit stands (documented pitfall), no retry.
        return JSONResponse(status_code=502, content={"detail": f"ollama: {exc}"})
