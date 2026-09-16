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

Debit-before-forward, exactly-once per call: on a forwarding failure we do
NOT retry the debit path — the call fails (a dropped call may charge; accepted
and documented, SPEC §13 pitfall 2).
"""

import os

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

JUDGE_URL = os.environ.get("JUDGE_URL", "http://judge:8000").rstrip("/")
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://ollama:11434").rstrip("/")
COST_LLM_CALL = int(os.environ.get("COST_LLM_CALL", "1"))

app = FastAPI()
_client = httpx.Client(timeout=600.0)


@app.get("/health")
async def health():
    """Readiness for the worm's wait_for_ollama: is ollama up + model pulled?"""
    try:
        r = _client.get(OLLAMA_HOST + "/api/tags", timeout=10.0)
        r.raise_for_status()
        return {"ok": True, "models": [m.get("name") for m in r.json().get("models", [])]}
    except Exception as exc:
        return JSONResponse(status_code=503, content={"ok": False, "detail": str(exc)})


@app.get("/api/tags")
async def tags():
    """Free passthrough so tools.ollama_ready works unchanged against llmgw."""
    r = _client.get(OLLAMA_HOST + "/api/tags", timeout=10.0)
    return r.json()


def _debit(instance_id: str, token: str) -> tuple[bool, int]:
    """Ask the judge to debit COST_LLM_CALL. Returns (ok, balance)."""
    r = _client.post(
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

    ok, balance = _debit(instance_id, token)
    if not ok:
        # SPEC §4.2/§5.2: the agent's death signal. ollama is never called.
        return JSONResponse(
            status_code=402,
            content={"detail": "insufficient credits", "balance": balance},
        )

    # Enforce the v0.1 LLM contract (SPEC-v0.2 §6): stream off, capped output.
    payload["stream"] = False
    opts = payload.setdefault("options", {})
    opts.setdefault("temperature", 0.4)
    opts.setdefault("num_predict", 512)

    try:
        r = _client.post(OLLAMA_HOST + "/api/generate", json=payload)
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        # Forwarding failure: the debit stands (documented pitfall), no retry.
        return JSONResponse(status_code=502, content={"detail": f"ollama: {exc}"})
