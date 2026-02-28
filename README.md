# skewlog

Before you upgrade, check the skew.

skewlog is a self-hosted web app for Helm chart version diffing. Select a chart, pick your current version, and instantly see exactly what changed in `values.yaml`, `Chart.yaml`, and all templates — before you touch your cluster.

## Features

- **13 pre-loaded SRE charts**: cert-manager, ingress-nginx, kube-prometheus-stack, argo-cd, external-secrets, metrics-server, velero, sealed-secrets, grafana, loki, tempo, istio-base, istiod
- **Helm chart diff**: fetches public chart tarballs directly from Helm repos — no auth, no tokens
- **Breaking change detection**: scans release notes for `BREAKING CHANGE`, `⚠️`, `action required`, `migration guide`, etc.
- **SQLite cache**: versions and chart files stored locally — fast after first sync
- **Daily background job**: checks for new releases every 24h
- **Add custom repos**: any public Helm repo works

## Local Development

```bash
pip install -r requirements.txt
python app.py
```

Open http://localhost:5000

## Usage

1. Select a chart from the top dropdown
2. Click a version on the left sidebar (your current version)
3. Hit **Compare** — automatically diffs against latest
4. Switch between **Diff**, **Release Notes**, and **Between Versions** tabs

| Tab | What it shows |
|-----|---------------|
| **Diff** | File-by-file unified diff across all chart files |
| **Release Notes** | Release notes with breaking changes highlighted |
| **Between Versions** | Every version in the range, flagged for breaking changes |

## Production Deploy

See `deploy/` for nginx config, systemd service, and GitHub Actions workflow.

```bash
PORT=8080 python app.py  # custom port
```

SQLite DB is created automatically as `skewlog.db` next to `app.py`. Delete to reset.
