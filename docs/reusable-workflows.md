# DustBowl-Games Reusable Workflows

> **Single Source of Truth:** `DustBowl-Games/.github` is the canonical organization hub for reusable GitHub Actions workflows. It supersedes the legacy `DustBowl-Games/ci-workflows` GitLab templates and the duplicate `reusable-*` workflows in `DustBowl-CD`.

All reusable workflows are `workflow_call`-only, **100% zero-cost OSS** (no paid GHAS, CodeQL, Gitleaks license, or third-party SaaS tokens), and default to self-hosted `DB-Runner01` (`["self-hosted","Linux","X64","dustbowl-linux"]`). Callers handling fork PRs should pass `ubuntu-latest` for untrusted `pull_request` events.

---

## 1. Self-Hosted Security Gate (`_security-gate.yml`)

Runs OSS Gitleaks (`ghcr.io/gitleaks/gitleaks` container), OSS Trivy filesystem/IaC & optional container image scan, OSS Semgrep SAST (`--metrics=off`), and Dockerfile non-root/`latest` hardening checks.

```yaml
jobs:
  security:
    uses: DustBowl-Games/.github/.github/workflows/_security-gate.yml@main
    with:
      runner_labels: ${{ (github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name != github.repository) && '["ubuntu-latest"]' || '["self-hosted","Linux","X64","dustbowl-linux"]' }}
      semgrep_blocking: true
    permissions:
      contents: read
```

## 2. Code Quality & Anti-Slop Gates (`_code-quality-gates.yml`)

Restores Conventional Commits + AI buzzword/watermark linting, Lizard cyclomatic complexity guard, `jscpd` duplicate code scan, NPM lockfile + Knip dead-code guard, PostgreSQL migration `CONCURRENTLY` index guard, and optional `helm lint`.

```yaml
jobs:
  quality:
    uses: DustBowl-Games/.github/.github/workflows/_code-quality-gates.yml@main
    with:
      runner_labels: '["self-hosted","Linux","X64","dustbowl-linux"]'
      run_duplication: true
      run_postgres_migration_guard: true
    permissions:
      contents: read
```

## 3. Factual Claims & No-Fake-Promises Gate (`_factual-claims-gate.yml`)

Blocks unapproved SLA percentages, response-time guarantees (`same business day`, `within 24 hours`, `< 2 hour`, `priority ticket dispatch`), `24/7` claims, hardcoded fiber/ms latency numbers, refund/uptime guarantees, and unverified compliance badges (`SOC 2`, `NIST 800-88`, `Fortune 500`) unless explicitly allowlisted in `config/verified-claims-allowlist.json`.

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

## 4. .NET Service CI + SBOM + GHCR (`_dotnet-service-ci.yml`)

Builds, audits NuGet packages for High/Critical vulnerabilities, runs tests, scans OCI images with OSS Trivy, generates CycloneDX SBOMs, and pushes to GHCR on `push`.

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
      publish_image: ${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}
    permissions:
      contents: read
      packages: write
```

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
