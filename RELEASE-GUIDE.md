# Release guide

How to cut a versioned release of **couch-auth-proxy** and publish the server Docker image to GitHub Container Registry (GHCR).

## Overview

1. `scripts/release.sh` bumps `package.json`, commits, creates an annotated git tag (`vX.Y.Z`), pushes, and opens a GitHub Release.
2. Publishing that release triggers [`.github/workflows/publish.yml`](.github/workflows/publish.yml).
3. The workflow builds [`Dockerfile`](Dockerfile) (the main server process) and pushes to GHCR.

CI quality/integration checks ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) still run on pushes and pull requests; they are separate from image publish.

## Prerequisites

- Clean git working tree on `main` or `master`
- Push access to the GitHub repo
- [GitHub CLI](https://cli.github.com/) (`gh`) authenticated (`gh auth login`)
- Node.js available locally (used only to edit `package.json`)

Package visibility: the default `GITHUB_TOKEN` can push images to GHCR for this repository. First pull of a private package may require a PAT with `read:packages`; public repos can make the package public under **Packages → Package settings**.

## Cut a release

```bash
# patch: 2.0.0 -> 2.0.1
./scripts/release.sh patch

# minor: 2.0.1 -> 2.1.0
./scripts/release.sh minor

# major: 2.1.0 -> 3.0.0
./scripts/release.sh major

# explicit version
./scripts/release.sh 2.2.0
```

Useful flags:

| Flag        | Effect                                               |
| ----------- | ---------------------------------------------------- |
| `--dry-run` | Print the plan; change nothing                       |
| `--no-push` | Commit + tag locally only (no push / GitHub Release) |

`--no-push` finish later with:

```bash
git push origin main vX.Y.Z   # or master
gh release create vX.Y.Z --title vX.Y.Z --generate-notes
```

Creating (or publishing) the GitHub Release is what starts the publish workflow—not the git tag alone.

## Image tags on GHCR

Image name (lowercase):

```text
ghcr.io/<owner>/<repo>
```

For this repository that is `ghcr.io/peterbaker0/couch-auth-proxy`.

For a release tag `v2.1.3` (stable, not a pre-release), the workflow applies:

| Tag           | Meaning                                         |
| ------------- | ----------------------------------------------- |
| `2.1.3`       | Exact semver (no leading `v`)                   |
| `2.1`         | Major.minor floating tag                        |
| `2`           | Major floating tag                              |
| `latest`      | Latest stable release (omitted for prereleases) |
| `sha-<short>` | Short commit SHA of the release commit          |

Pre-releases (GitHub Release marked as pre-release, e.g. `v2.1.3-rc.1`) get the semver / major.minor / major / sha tags but **not** `latest`.

## Pull and run

```bash
docker pull ghcr.io/peterbaker0/couch-auth-proxy:2.0.0
# or
docker pull ghcr.io/peterbaker0/couch-auth-proxy:latest
```

Point compose at the published image instead of a local build:

```yaml
services:
  couch-auth-proxy:
    image: ghcr.io/peterbaker0/couch-auth-proxy:2.0.0
    # ...same env / ports as docker-compose.yml
```

## Manual / ad-hoc publish

Normally you should not need this. To re-run publish for an existing release, open the failed or prior **Publish** workflow run on GitHub and use **Re-run jobs**, or edit the release (republish). The workflow listens for `release` → `published` only.

## Checklist

- [ ] `main`/`master` is green on CI
- [ ] Changelog / release notes content is ready (or rely on `--generate-notes`)
- [ ] `./scripts/release.sh patch|minor|major` (or explicit version)
- [ ] Confirm the **Publish** workflow succeeded
- [ ] `docker pull ghcr.io/<owner>/<repo>:<version>` and smoke-test
