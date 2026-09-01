#!/usr/bin/env bash
# Auto-release: bump the patch version, update CHANGELOG.md, commit, tag, push.
#
# Runs in CI on pushes to main and the 2h schedule (the `release` job in
# .github/workflows/ci.yml). The publish job is chained via needs: on this
# job's outputs (released/tag), so the default GITHUB_TOKEN is enough —
# no PAT secret required.
#
# Changelog rules:
# - a curated `## Unreleased` section becomes the new version's notes;
# - otherwise notes are generated from commit subjects since the last tag;
# - a fresh empty `## Unreleased` is appended at the end.
#
# Retries the whole bump from origin/main when another push races it.
set -euo pipefail

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"

# Emit a job output line when running under Actions (no-op locally).
out() { if [ -n "${GITHUB_OUTPUT:-}" ]; then printf '%s\n' "$1" >>"$GITHUB_OUTPUT"; fi; }

# Loop guard only: runs with nothing new since the last tag are skipped.
# No time-based coalescing — npm has no pub.dev-style publish quota, so
# every push to main releases immediately.
git fetch origin main --tags --quiet
last_tag=$(git tag --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || true)
if [ -n "$last_tag" ]; then
  pending=$(git rev-list --count "$last_tag..origin/main")
  if [ "$pending" -eq 0 ]; then
    out "released=false"
    echo "Auto-release: nothing new since $last_tag, skipping."
    exit 0
  fi
fi

for attempt in 1 2 3; do
  git fetch origin main
  git reset --hard origin/main

  current=$(node -p "require('./package.json').version")
  # Other workflows may tag releases without bumping package.json — when tags
  # raced ahead, bump from the latest tag instead, or every run dies on
  # "tag already exists".
  latest_tag=$(git tag --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || true)
  if [ -n "$latest_tag" ]; then
    tag_version="${latest_tag#v}"
    if [ "$(printf '%s\n%s\n' "$current" "$tag_version" | sort -V | tail -1)" = "$tag_version" ]; then
      current="$tag_version"
    fi
  fi
  IFS='.' read -r major minor patch <<< "$current"
  next="$major.$minor.$((patch + 1))"
  echo "Auto-release: v$current -> v$next (attempt $attempt)"

  last_tag=$(git tag --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || true)
  if [ -n "$last_tag" ]; then range="$last_tag..HEAD"; else range="HEAD"; fi
  bullets=$(git log "$range" --pretty='- %s' --no-merges | grep -v '^- chore(release):' || true)
  [ -z "$bullets" ] && bullets="- Maintenance release."

  NEXT="$next" BULLETS="$bullets" python3 - <<'PY'
import os
import re

nxt = os.environ["NEXT"]
bullets = os.environ["BULLETS"].strip()
path = "CHANGELOG.md"
text = open(path, encoding="utf-8").read() if os.path.exists(path) else "# Changelog\n\n"
section = f"## {nxt}\n\n{bullets}\n"

m = re.search(r"^## Unreleased[ \t]*$", text, re.M)
if m:
    rest = text[m.end():]
    head = re.search(r"^## ", rest, re.M)
    body = rest[: head.start()] if head else rest
    tail = rest[head.start():] if head else ""
    if body.strip():
        # Curated Unreleased content becomes this release's notes.
        new_section = f"## {nxt}\n" + body.rstrip() + "\n"
    else:
        new_section = section
    text = text[: m.start()] + new_section + ("\n" + tail if tail else "")
else:
    text = text.rstrip() + "\n\n" + section

text = text.rstrip() + "\n\n## Unreleased\n"
open(path, "w", encoding="utf-8").write(text)
PY
  sed -i "0,/^  \"version\": .*/s//  \"version\": \"$next\",/" package.json
  # npm ci in the publish job requires the lockfile to carry the new version.
  npm install --package-lock-only --ignore-scripts

  git add package.json package-lock.json CHANGELOG.md
  git commit -m "chore(release): v$next"
  # Annotated tag: --follow-tags only pushes annotated tags, lightweight
  # ones stay local. --atomic makes main+tag land together or not at all.
  git tag -a "v$next" -m "Release v$next"
  if git push --atomic origin main --follow-tags; then
    out "released=true"
    out "tag=v$next"
    # GitHub Release page for the tag (GITHUB_TOKEN suffices — creating a
    # release is not a push event and triggers no recursion). Notes are
    # commit-derived; CHANGELOG.md stays the curated source.
    if command -v gh >/dev/null 2>&1; then
      gh release create "v$next" --title "v$next" --generate-notes || \
        echo "WARN: gh release create failed (tag exists; release page skipped)"
    fi
    echo "Released v$next"
    exit 0
  fi
  echo "Push raced with another commit, rebasing and retrying..."
  git tag -d "v$next" >/dev/null 2>&1 || true
done

echo "Auto-release failed after 3 attempts"
exit 1
