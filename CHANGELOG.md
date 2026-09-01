# Changelog

## 0.1.1


- Extracted from the dap monorepo (adapters/omp-extension) into this standalone package.

## 0.1.2

- README: document the automated release + trusted-publishing pipeline.

## 0.1.3

- feat(release): immediate release+publish per push — drop the 2h coalesce window inherited from fah (pub.dev quota does not apply to npm); drop the catch-up cron
- fix(ci): manual tag path backfills the GitHub Release page — a pushed v* tag skipped the release job, leaving the Releases list and badge one version behind npm

## Unreleased
