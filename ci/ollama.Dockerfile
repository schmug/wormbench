FROM ollama/ollama:0.6.8
# Model blobs downloaded ahead of time by the CI job (see .github/workflows/smoke.yml).
COPY .ollama-ci /root/.ollama
