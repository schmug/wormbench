# Contributing to wormbench

Keep changes focused and explain the problem they solve. For a new feature or
benchmark behavior change, open an issue describing the proposal first.

wormbench is a **research and authorized-testing** tool: contributions are
assumed to serve that purpose (see the notice in README.md).

## Local checks

Install Python 3.12, Bash, Git, and Docker with the Compose v2 plugin. From the
repository root, run:

```bash
bash ci/check.sh
```

This checks Python and shell syntax, JSON fixtures, and the baseline, ClamAV,
and CI Compose combinations. It does not start containers or download models.
GitHub Actions runs the same checks on pull requests and pushes to `main`.

For changes to runtime behavior, also run the relevant benchmark profile:

```bash
./cli/wormbench run --mode smoke --protections none
./cli/wormbench run --mode smoke --protections protections/clamav
```

These commands start the range and may download images and models. Use only
the disposable benchmark targets on a machine you control. Record the model,
protection configuration, command, and relevant score fields in your PR; explain
any skipped runs. The smoke workflow separately exercises the baseline end to end.

## Benchmark changes

Treat target versions, seeded vulnerabilities, and scoring behavior as benchmark
inputs. Explain how changes affect reproducibility and existing results. Update
the [README](README.md) and [protection contract](protection-slot/README.md) when
their documented behavior changes. Dependency updates must be reviewed with the
same care; Dependabot proposes weekly GitHub Actions and Python updates.

## Pull requests

Use the PR template and include validation results. Keep generated `out/` data,
local `.env` files, credentials, and model caches out of commits. Redact sensitive
data from logs shared in issues or PRs. Follow `.editorconfig` for new files and
avoid unrelated formatting changes.
