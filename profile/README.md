# DustBowl Games

We build game server communities that last — on infrastructure that actually holds up.

DustBowl Games is a subscription-based platform for serious players. Custom whitelisted servers,
unique mods, and real DevOps behind everything. We stream the infrastructure work live and
document it publicly because we have nothing to hide.

---

## The Stack

Our production cluster runs on [Harvester HCI](https://harvesterhci.io/) with
[RKE2](https://docs.rke2.io/) — 3 control-plane nodes and 3 workers, all on-premise.

| Layer | Technology |
|-------|-----------|
| Hypervisor | Harvester HCI |
| Kubernetes | RKE2 |
| Storage | Longhorn (distributed, 3-replica) |
| Load Balancing | MetalLB (Layer 2) |
| Ingress | Traefik |
| GitOps | ArgoCD |
| Monitoring | Prometheus + Grafana |
| Databases | CloudNativePG (PostgreSQL) |
| Backups | Backblaze B2 via Rancher Backup Operator + CNPG WAL archiving |
| Admission Control | Kubewarden |
| Game Management | Wisp.gg + AMP |

---

## What We Publish Here

- Infrastructure scripts and operational tooling
- Kubernetes manifests and Helm values (sanitized)
- Runbooks and architecture documentation
- Build-in-public notes from the cluster

Internal cluster documentation lives in a self-hosted Gitea instance.

---

## Find Us

| | |
|-|-|
| 🌐 Website | [dustbowl.games](https://dustbowl.games) |
| 🎮 Apply | [join.dustbowl.games](https://join.dustbowl.games) |
| 💬 Discord | [discord.gg/dustbowlgames](https://discord.gg/dustbowlgames) |
| 📺 Twitch | [twitch.tv/dustbowlgames](https://twitch.tv/dustbowlgames) |
| 📊 Status | [uptime.dustbowl.games](https://uptime.dustbowl.games) |
