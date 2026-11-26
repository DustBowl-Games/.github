# DustBowl-Games Reusable Workflows

All workflows in `DustBowl-Games/.github` are `workflow_call`-only and run on self-hosted `DB-Runner01` (`[self-hosted, Linux, X64, dustbowl-linux]`) for **\$0/min**.

## 1. Self-Hosted Security Gate (`_security-gate.yml`)

Replaces paid GHAS Code Security & Secret Protection with Gitleaks + Trivy + Semgrep:

```yaml
jobs:
  security:
    uses: DustBowl-Games/.github/.github/workflows/_security-gate.yml@main
    permissions:
      contents: read
```

## 2. .NET Service CI + SBOM + GHCR (`_dotnet-service-ci.yml`)

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

## 3. Automated Release Notes (`_release-notes.yml`)

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
