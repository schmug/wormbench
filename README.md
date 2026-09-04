# wormbench v0.1

A Docker Compose–based security benchmark that measures how well an arbitrary
protection container stops an **AI-driven autonomous worm** from compromising a
small fixed target network and exfiltrating a flag from a "secrets" container.

**Mental model:** red container (worm, LLM-driven via ollama) attacks
targets, purple container (judge) records ground truth, your container
defends, and the CLI arena-loops both and emits a scorecard.

- Foothold: `victim-1` — OWASP Juice Shop (SQLi → admin login)
- Pivot: `victim-2` — sshd + nginx; SSH credential reuse
- Objective: `secrets` — redis holding the flag
- The worm's decisions are LLM-driven (qwen2.5); the harness is fully
  deterministic (fixed vuln set, pinned images, fixed attack graph).

## Quickstart (3 commands)

```bash
./cli/wormbench run --protections none                      # baseline: no defense
./cli/wormbench run --protections protections/clamav         # vs. a protection
./cli/wormbench score                                       # re-render out/report.html
```

Then open `out/report.html`. Each run writes `out/run-NNN/` (actions.jsonl,
protection.jsonl, score.json); everything is disposable — `./cli/wormbench
down && docker volume ls | grep wormbench` shows zero leftovers.

Useful options: `--mode smoke` (1 run, 15 min, qwen2.5:1.5b), `--runs N`
(N ≥ 2 enables the control/false-positive phase), `--budget-min M`,
`--eicar-anchor` (worm stages an eicar.com test file to validate the
protection event path — off by default).

## Adding a protection

Write a compose partial and point `--protections` at it. The full vendor
contract is in [protection-slot/README.md](protection-slot/README.md); a
minimal reference lives in [protections/clamav/](protections/clamav/)
(≈40 lines: mount `shared-artifacts :ro`, scan it, POST detections to
`judge:8000/events` with the `X-Judge-Token` from your env).

## How it scores

The judge (purple team) records token-authenticated worm actions, replica
beacons (delegated HMAC tokens), and protection events, then computes:
exfil success, blast radius, time-to-exfil, detection latency + coverage,
false positives (events during `ENABLED=0` control windows), LLM calls, and
wallclock. `judge/report.py` aggregates runs per protection config into
`out/report.html`.

## Repo layout

| Path | What |
|---|---|
| `cli/wormbench` | run/score/down driver |
| `judge/` | FastAPI event sink + scorer + HTML report |
| `worm/` | LLM-driven worm agent, tools, replica payload, advisories, attack graph |
| `victims/victim-2/` | pivot host (sshd/nginx/python3) |
| `protection-slot/` | vendor contract doc |
| `protections/clamav/` | reference protection |
| `compose-overrides/empty.yml` | `--protections none` |
| `.github/workflows/smoke.yml` | CI smoke profile (offline-safe, pre-baked model) |

## Current known results

Observed on the implementer's machine (Apple Silicon, Docker Desktop, model
qwen2.5:1.5b, single smoke runs):

| Config | Exfil rate | Detection coverage | FP (control) |
|---|---|---|---|
| none (baseline) | 1/1 smoke run (`exfil_success: true`, blast_radius 1) | — | — |
| clamav | worm still exfiltrates (ClamAV only sees staged files) | ~0.09 (T1105 via eicar anchor only) | 0 |
| none + `TEST_NO_CRED_HINT=1` | 0/1 — chain breaks at SSH (validates the LLM memory-stitching, not hardcoding) | — | — |

Regenerate with the quickstart commands above. The eicar anchor exists only
to validate the protection event path end-to-end; ClamAV missing everything
else (the on-message result) is expected for v0.1.

## Notes

- All benchmark containers run on `wormnet` (`internal: true`) — no internet
  at runtime. Exceptions per spec: image pulls, `freshclam`/ollama model pull
  at container *start* (via the `pullnet` side network). The judge also
  joins a small non-internal `judgenet` purely so Docker can publish its
  host scoring port (Docker does not publish ports for containers on
  internal-only networks); it only ever listens.
- `ollama/ollama:0.6` doesn't exist as a tag; images are pinned to
  `ollama/ollama:0.6.8`.
- `clamav/clamav` publishes amd64-only images; the reference protection
  sets `platform: linux/amd64` (emulated on arm64 hosts).
- The CLI waits a settle window (default 90s, `WORMBENCH_SETTLE_SEC`)
  after worm exit before scoring/teardown so asynchronous protection reports
  (e.g. ClamAV's 30s scan loop) are captured.
- Reference paper: arXiv:2606.03811
