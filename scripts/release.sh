#!/usr/bin/env bash
# Bump package.json, commit, tag, push, and publish a GitHub Release.
# Publishing a release triggers .github/workflows/publish.yml (GHCR image push).
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/release.sh <patch|minor|major|X.Y.Z> [--dry-run] [--no-push]

Bumps package.json version, commits, creates annotated tag vX.Y.Z, pushes to
origin, and creates a GitHub Release (which triggers the GHCR publish workflow).

Options:
  --dry-run   Show what would happen; do not write files or run git/gh
  --no-push   Commit and tag locally only (no git push, no gh release)
  -h, --help  Show this help
EOF
}

die() {
  echo "error: $*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

bump_semver() {
  local current="$1" kind="$2"
  local major minor patch
  IFS=. read -r major minor patch <<<"$current"
  case "$kind" in
    major) echo "$((major + 1)).0.0" ;;
    minor) echo "${major}.$((minor + 1)).0" ;;
    patch) echo "${major}.${minor}.$((patch + 1))" ;;
    *) die "internal: unknown bump kind '$kind'" ;;
  esac
}

DRY_RUN=0
NO_PUSH=0
BUMP=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h | --help)
      usage
      exit 0
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --no-push)
      NO_PUSH=1
      shift
      ;;
    patch | minor | major)
      [[ -z "$BUMP" ]] || die "bump kind already set to '$BUMP'"
      BUMP="$1"
      shift
      ;;
    [0-9]*.[0-9]*.[0-9]*)
      [[ -z "$BUMP" ]] || die "bump kind already set to '$BUMP'"
      BUMP="$1"
      shift
      ;;
    *)
      usage >&2
      die "unknown argument: $1"
      ;;
  esac
done

[[ -n "$BUMP" ]] || {
  usage >&2
  die "missing bump kind or version"
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

require_cmd git
require_cmd node
if [[ "$NO_PUSH" -eq 0 && "$DRY_RUN" -eq 0 ]]; then
  require_cmd gh
fi

[[ "$(git rev-parse --is-inside-work-tree 2>/dev/null)" == "true" ]] || die "not a git repository"
if [[ "$DRY_RUN" -eq 0 ]]; then
  [[ -z "$(git status --porcelain)" ]] || die "working tree is dirty; commit or stash first"
fi

BRANCH="$(git branch --show-current)"
if [[ "$DRY_RUN" -eq 0 ]]; then
  [[ "$BRANCH" == "main" || "$BRANCH" == "master" ]] ||
    die "must be on main or master (currently on '$BRANCH')"
fi

CURRENT="$(node -p "require('./package.json').version")"
[[ "$CURRENT" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
  die "package.json version '$CURRENT' is not plain semver X.Y.Z"

case "$BUMP" in
  patch | minor | major) NEXT="$(bump_semver "$CURRENT" "$BUMP")" ;;
  *)
    [[ "$BUMP" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "version must be X.Y.Z (got '$BUMP')"
    NEXT="$BUMP"
    ;;
esac

[[ "$NEXT" != "$CURRENT" ]] || die "next version equals current ($CURRENT)"

TAG="v${NEXT}"
if [[ "$DRY_RUN" -eq 0 ]] && git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null; then
  die "tag ${TAG} already exists"
fi

echo "Release plan:"
echo "  package.json: ${CURRENT} -> ${NEXT}"
echo "  commit:       chore: release ${TAG}"
echo "  tag:          ${TAG} (annotated)"
if [[ "$NO_PUSH" -eq 1 ]]; then
  echo "  remote:       skipped (--no-push)"
else
  echo "  remote:       git push origin ${BRANCH} ${TAG}"
  echo "  github:       gh release create ${TAG}"
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "dry-run: no changes made"
  exit 0
fi

node <<EOF
const fs = require("node:fs");
const path = "package.json";
const pkg = JSON.parse(fs.readFileSync(path, "utf8"));
pkg.version = "${NEXT}";
fs.writeFileSync(path, JSON.stringify(pkg, null, 2) + "\n");
EOF

git add package.json
git commit -m "chore: release ${TAG}"
git tag -a "${TAG}" -m "Release ${TAG}"

if [[ "$NO_PUSH" -eq 1 ]]; then
  echo "Created local commit and tag ${TAG}. Push and publish when ready:"
  echo "  git push origin ${BRANCH} ${TAG}"
  echo "  gh release create ${TAG} --title ${TAG} --generate-notes"
  exit 0
fi

git push origin "${BRANCH}" "${TAG}"
gh release create "${TAG}" --title "${TAG}" --generate-notes

echo
echo "Released ${TAG}."
echo "Publish workflow will push the image to:"
echo "  ghcr.io/$(git remote get-url origin | sed -E 's#.*[:/]([^/]+)/([^/.]+)(\.git)?$#\1/\2#' | tr '[:upper:]' '[:lower:]'):${NEXT}"
