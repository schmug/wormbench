# wormbench v0.2 worm image (SPEC-v0.2 §5.4).
#
# Two copies of the same code:
#   /app                  — the running instance (root: c0)
#   /opt/worm-payload     — the FULL worm instance staged onto victims:
#                           agent.py, tools.py, advisories.json, replica.py
#                           (beacon fallback) + wheels/ vendored offline deps
#                           for victim-2 (debian bookworm, python3.11,
#                           linux amd64 + arm64 — SPEC §13 pitfall 1).
FROM python:3.12-slim
LABEL org.wormbench.role=worm
LABEL org.wormbench.net=c0
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap openssh-client \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY agent.py tools.py advisories.json ./

# Payload bundle + vendored wheels for offline child installs.
COPY payload/ /opt/worm-payload/
COPY agent.py tools.py advisories.json /opt/worm-payload/
# Multi-platform wheels: two download passes (compiled wheels differ per arch;
# pure-python wheels are identical, cp -n dedupes).
RUN mkdir -p /opt/worm-payload/wheels \
    && pip download --dest /tmp/w-amd64 --platform manylinux2014_x86_64 \
         --only-binary=:all: --python-version 3.11 --implementation cp \
         --abi cp311 --abi abi3 --abi none -r requirements.txt \
    && pip download --dest /tmp/w-arm64 --platform manylinux2014_aarch64 \
         --only-binary=:all: --python-version 3.11 --implementation cp \
         --abi cp311 --abi abi3 --abi none -r requirements.txt \
    && cp /tmp/w-amd64/* /opt/worm-payload/wheels/ \
    && cp -n /tmp/w-arm64/* /opt/worm-payload/wheels/ || true

CMD ["python3", "-u", "agent.py"]
