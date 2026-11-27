# DustBowl-Games Reusable Workflows

> **Single Source of Truth:** `DustBowl-Games/.github` is the canonical organization hub for reusable GitHub Actions workflows. It supersedes the legacy `DustBowl-Games/ci-workflows` GitLab templates and the duplicate `reusable-*` workflows in `DustBowl-CD`.

All reusable workflows are `workflow_call`-only, **100% zero-cost OSS** (no paid GHAS, CodeQL, Gitleaks license, or third-party SaaS tokens), and default to self-hosted `DB-Runner01` (`["self-hosted","Linux","X64","dustbowl-linux"]`). Callers handling fork PRs should pass `ubuntu-latest` for untrusted `pull_request` events.

> **Runner Note (`DB-Runner01` Node cache):** Keep `actions/setup-node` pinned to `49933ea5288caeca8642d1e84afbd3f7d6820020` (`v4.4.0`). Newer `actions/setup-node` versions attempt to pull/unpack a corrupted `node/22.23.5/x64` cache on `DB-Runner01`.

---

## Fork-PR Runner Routing

All public or fork-eligible repositories should route untrusted fork PRs away from self-hosted runners:

```yaml
runner_labels: ${{ (github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name != github.repository) && '["ubuntu-latest"]' || '["self-hosted","Linux","X64","dustbowl-linux"]' }}
```

---

## 1. Self-Hosted Security Gate (`_security-gate.yml`)

Runs OSS Gitleaks (`ghcr.io/gitleaks/gitleaks` container), OSS Trivy filesystem/IaC & optional container image scan, OSS Semgrep SAST (`--metrics=off`, combining `semgrep_config`, org `.semgrep/antislop-rules.yml`, and caller `.semgrep/antislop-rules.yml` without duplicate-rule collisions), Dockerfile multi-stage/non-root/digest safety checks (`audit-infra-safety.py`), and optional Kubernetes/Helm safety checks.

### Inputs
| Input | Type | Default | Purpose |
|---|---|---|---|
| `runner_labels` | string | `["self-hosted","Linux","X64","dustbowl-linux"]` | Runner labels JSON array |
| `fail_on_severity` | string | `CRITICAL,HIGH` | Trivy fail severities |
| `image_ref` | string | `""` | Optional OCI image to scan |
| `run_semgrep` | boolean | `true` | Run Semgrep OSS scan |
| `semgrep_config` | string | `p/security-audit` | Comma/space-separated Semgrep configs |
| `semgrep_blocking` | boolean | `false` | Fail on Semgrep `ERROR` findings |
| `semgrep_baseline_commit` | string | `""` | Optional commit/ref or `auto` for PR base SHA |
| `check_dockerfile` | boolean | `true` | Scan all `Dockerfile*` / `*.Dockerfile` |
| `require_pinned_digest` | boolean | `false` | Require `@sha256:` digests on `FROM` |
| `check_k8s_helm` | boolean | `false` | Scan Helm/K8s YAML for unsafe contexts and plaintext TLS |
| `helm_chart_dir` | string | `""` | Optional Helm/K8s directory override |
| `baseline_file` | string | `""` | Optional JSON baseline for pre-existing infra waivers |

```yaml
jobs:
  security:
    uses: DustBowl-Games/.github/.github/workflows/_security-gate.yml@main
    with:
      runner_labels: ${{ (github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name != github.repository) && '["ubuntu-latest"]' || '["self-hosted","Linux","X64","dustbowl-linux"]' }}
      semgrep_blocking: true
      semgrep_baseline_commit: auto
    permissions:
      contents: read
```

---

## 2. Code Quality & Anti-Slop Gates (`_code-quality-gates.yml`)

Runs Conventional Commits + AI buzzword/watermark linting (`verify-commit-msg.py`), CI integrity & anti-bypass guard (`audit-ci-integrity.mjs`), workflow hygiene (`audit-workflows.py` + SHA256-verified `actionlint` v1.7.12 and `shellcheck` v0.11.0), anti-AI-slop & cleanliness gate (`audit-ai-smells.py`), optional baseline ratchet (`audit-baselines.mjs`), Lizard cyclomatic complexity guard, `jscpd` duplicate code scan, NPM lockfile + Knip dead-code guard, PostgreSQL migration `CONCURRENTLY` index guard, and optional `helm lint`.

### Inputs
| Input | Type | Default | Purpose |
|---|---|---|---|
| `runner_labels` | string | `["self-hosted","Linux","X64","dustbowl-linux"]` | Runner labels JSON array |
| `run_commit_lint` | boolean | `true` | Validate Conventional Commits & anti-slop |
| `run_ci_integrity` | boolean | `true` | Block `Skip=`, `continue-on-error: true`, masking, suppressions, unapproved test deletion |
| `ci_integrity_baseline` | string | `""` | Optional JSON baseline for CI integrity |
| `run_workflow_hygiene` | boolean | `true` | Run `actionlint` + workflow contract checks |
| `workflow_hygiene_baseline` | string | `""` | Optional JSON baseline for workflow hygiene |
| `run_ai_smells` | boolean | `true` | Run anti-AI-slop, stub, dash, and cleanliness checks |
| `ai_smells_mode` | string | `diff` | `diff` (PR added lines) or `all` |
| `ai_smells_baseline` | string | `""` | Optional JSON baseline for pre-existing smells |
| `allow_markdown_dashes` | boolean | `false` | Allow em/en-dashes in Markdown prose (never in code) |
| `run_baseline_ratchet` | boolean | `false` | Enforce non-growing baseline/ignore files on PRs |
| `baseline_paths` | string | `""` | Optional comma-separated baseline/ignore paths |
| `run_complexity` | boolean | `true` | Lizard complexity check on changed files |
| `max_cyclomatic_complexity` | number | `20` | Max cyclomatic complexity |
| `run_duplication` | boolean | `false` | `jscpd` duplicate code scan |
| `duplication_threshold` | number | `10` | Max duplication percentage |
| `duplication_paths` | string | `.` | Space-separated paths for `jscpd` |
| `run_dead_code` | boolean | `false` | Run Knip dead-code scan |
| `run_dependency_drift` | boolean | `true` | Verify `npm ci --ignore-scripts` |
| `run_postgres_migration_guard` | boolean | `false` | Block non-concurrent `CREATE INDEX` in migrations |
| `run_k8s_helm_lint` | boolean | `false` | Run `helm lint` |
| `helm_chart_dir` | string | `""` | Helm chart directory |

```yaml
jobs:
  quality:
    uses: DustBowl-Games/.github/.github/workflows/_code-quality-gates.yml@main
    with:
      runner_labels: '["self-hosted","Linux","X64","dustbowl-linux"]'
      run_duplication: true
      run_postgres_migration_guard: true
      run_baseline_ratchet: true
    permissions:
      contents: read
```

---

## 3. Factual Claims & No-Fake-Promises Gate (`_factual-claims-gate.yml`)

Scans `$GITHUB_WORKSPACE` (via `--repo-root "$GITHUB_WORKSPACE"`) to block unapproved SLA percentages, response-time guarantees (`same business day`, `within 24 hours`, `< 2 hour`, `priority ticket dispatch`), `24/7` claims, hardcoded fiber/ms latency numbers, refund/uptime guarantees, and unverified compliance badges (`SOC 2`, `NIST 800-88`, `Fortune 500`) unless explicitly allowlisted in `config/verified-claims-allowlist.json`.

```yaml
jobs:
  factual-claims:
    uses: DustBowl-Games/.github/.github/workflows/_factual-claims-gate.yml@main
    with:
      allowlist_path: config/verified-claims-allowlist.json
      scan_all: true
    permissions:
      contents: read
```

---

## 4. .NET Service CI + SBOM + GHCR (`_dotnet-service-ci.yml`)

Builds, enforces `NuGetAudit` (`low`/`moderate`/`high`/`critical`), optionally checks `dotnet format --verify-no-changes` and compiler warning strictness, runs tests, scans OCI images with OSS Trivy, generates CycloneDX SBOMs, and pushes to GHCR on `push`.

### Additional Inputs
| Input | Type | Default | Purpose |
|---|---|---|---|
| `run_format_check` | boolean | `false` | Run `dotnet format --verify-no-changes --no-restore` |
| `nuget_audit_level` | string | `high` | `low`, `moderate`, `high`, or `critical` |
| `treat_warnings_as_errors` | boolean | `false` | Pass `-p:TreatWarningsAsErrors=true` |
| `warning_level` | string | `""` | Optional MSBuild `-p:WarningLevel=<n>` |
| `enforce_code_style` | boolean | `false` | Pass `-p:EnforceCodeStyleInBuild=true` |

```yaml
jobs:
  ci:
    uses: DustBowl-Games/.github/.github/workflows/_dotnet-service-ci.yml@main
    with:
      project_path: MyService.csproj
      dotnet_version: "10.0.x"
      sdk_image: "mcr.microsoft.com/dotnet/sdk:10.0"
      helm_chart_path: helm/my-service
      image_name: ghcr.io/dustbowl-games/my-service
      run_format_check: true
      treat_warnings_as_errors: true
      publish_image: ${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}
    permissions:
      contents: read
      packages: write
```

---

## 5. Automated Release Notes (`_release-notes.yml`)

```yaml
on:
  push:
    tags: ["v*"]

jobs:
  release:
    uses: DustBowl-Games/.github/.github/workflows/_release-notes.yml@main
    permissions:
      contents: write
```

---

## 6. Baseline Ratchet & Recommended Repository Rulesets

- **Baseline Ratchets:** Whenever a repository initializes a new baseline or ignore file (`.trivyignore`, `.gitleaksignore`, `.semgrepignore`, `config/*baseline*.json`, `config/*allowlist*.json`), `audit-baselines.mjs` requires `Allow-Baseline-Init: #<issue>` (or full issue URL) in commit messages or the PR body, and ensures subsequent PRs can only keep or shrink entry counts.
- **Test Removal Approval:** Deleting `*Tests.cs`, `*.test.mjs`, or `test_*.py` files requires `Allow-Test-Removal: <reason>` in commit messages or the PR body.
- **Recommended Branch / Ruleset Settings (for repository admins):**
  - Require pull request before merging (`required_linear_history: true`, squash or rebase merge, automatic branch deletion on merge).
  - Require status checks to pass before merging (including the Security Gate and Code Quality & Anti-Slop Gates job contexts).
  - Require fork PR workflows to route `pull_request` jobs from forks to `ubuntu-latest` rather than `self-hosted`.
  - Keep `actions/checkout` `persist-credentials: false` and explicit least-privilege `permissions:` across all workflows.
