# wormbench protection slot — vendor integration contract (v0.1)

A **protection** is a Docker Compose *partial file* that adds your security
product to the wormbench attack range. It is merged into the base range by the
runner:

```
docker compose -f docker-compose.yml -f <your-partial.yml> up -d --wait
```

(Use `wormbench run --protections <path-to-your-partial.yml>` to exercise it.)

## Guarantees your container receives

1. **Network**: attach to `wormnet` (compose service-level key `wormnet`).
   The compose project is fixed to `wormbench`, so the concrete network name
   is `wormbench_wormnet` — it is `internal: true`, so you see *all* attack
   traffic but your container cannot reach the internet at runtime.
   *Exception:* you may additionally attach to `pullnet` (non-internal) **only
   for start-time updates** (e.g. signature DB downloads like freshclam). This
   mirrors the benchmark's own rules for ollama model pulls.
2. **Filesystem surface**: the volume `shared-artifacts` (concrete name
   `wormbench_shared-artifacts`) is available; mount it anywhere you like,
   preferably read-only (`:ro`). Every payload the worm stages onto a victim
   appears under `…/artifacts/<RUN_ID>/<target>/`. **You must not write to
   this volume** (v0.1: ro only).
3. **Event sink**: report detections with

   ```
   POST http://judge:8000/events
   X-Judge-Token: $JUDGE_TOKEN     (injected into your container env)
   Content-Type: application/json

   {"t": 1718000230.5, "run": "<RUN_ID>", "verdict": "suspicious|malicious|benign",
    "confidence": 0.7, "technique": "T1105",
    "object": "/shared/artifacts/run-001/victim-2/replica.py",
    "note": "what you saw", "vendor": "your-product"}
   ```

   Only `suspicious` and `malicious` verdicts count as detections. Tag the
   MITRE technique when you can (any ATT&CK ID, or omit the field). `RUN_ID`
   is injected into your env. The judge offers **no hint endpoints** beyond
   `/health` — you must find the worm yourself.
4. **Control runs**: in some runs the worm sleeps (`ENABLED=0`). The judge
   tracks these windows; any detection event you emit during them counts as a
   **false positive**. Stay quiet when nothing is happening.
5. **Prohibitions**: no networks besides `wormnet` (and `pullnet` for
   start-time updates only); no writes to `shared-artifacts`; do not interfere
   with other containers at runtime (the judge records; it never kills).
6. **Optional**: a read-only `/var/run/docker.sock` mount is *permitted* for
   EDR-style protections — every range container is labeled
   `org.wormbench.role` ∈ `worm | victim | secrets | judge | protection |
   infra`, so you can attribute activity to a role.

Your container must tolerate `docker compose down -v` at any time; runs are
fully disposable.

## Reference implementation

See `protections/clamav/` (compose.yml + report.sh) — a ~40-line drop-in that
scans `shared-artifacts` on a 30s loop and reports `FOUND` lines as
`malicious` protection events.
