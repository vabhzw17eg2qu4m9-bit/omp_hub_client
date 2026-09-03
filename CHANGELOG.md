# Changelog

## 0.1.1


- Extracted from the dap monorepo (adapters/omp-extension) into this standalone package.

## 0.1.2

- README: document the automated release + trusted-publishing pipeline.

## 0.1.3

- feat(release): immediate release+publish per push — drop the 2h coalesce window inherited from fah (pub.dev quota does not apply to npm); drop the catch-up cron
- fix(ci): manual tag path backfills the GitHub Release page — a pushed v* tag skipped the release job, leaving the Releases list and badge one version behind npm

## 0.1.4

- feat(install): pi/omp plugin-manifest support — pi+omp extensions manifests, canonical 'omp install npm:omp_hub_client' README install path, pi-package keywords

## 0.1.5

- fix(install): dial the hub only when a session starts — install/validation opens no connection (owner rule); fake ctx auto-fires session_start like real omp
- fix(install): unref reconnect timers + hub socket (keepalive.ts pattern) — omp plugin-install validation ran the factory with no session and the ref'd reconnect loop hung the install CLI forever; session semantics unchanged (50/50 green)
- fix(install): manifest points at committed src/index.ts (dist/ is gitignored — git-spec installs failed validation); tarball ships src+dist

## 0.1.6

- fix: extension inert without DAP_MASTER_SECRET

## Unreleased
