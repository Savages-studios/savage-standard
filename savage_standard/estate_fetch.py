"""Snapshot fetcher for PROOF-E1 — the operator-side half.

``fetch_snapshot(org, token)`` collects an estate snapshot (the input
of ``estate.build_attestation``) from the GitHub API using only the
standard library: every repo in the org (paginated), its default-
branch head SHA, its GROUND_TRUTH.md text via the contents API (None
on 404 — a missing ground truth is data for the attestation, not a
fetch error), and up to 5 latest workflow runs on the default branch.

This module is shipped for operators who hold a token; the CLI wires
it as ``savage-verify estate --org ORG --fetch`` with the token read
from ``$GITHUB_TOKEN``. The test suite never calls the network — it
proves only the token-missing refusal at the CLI boundary.
Savage-original, stdlib only.
"""
from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

API = "https://api.github.com"


def _get(path: str, token: str):
    req = urllib.request.Request(API + path, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "savage-standard-estate-fetch",
    })
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _get_or_none(path: str, token: str):
    """GET that maps 404 (and 409, GitHub's empty-repo / no-Actions
    answer) to None instead of raising."""
    try:
        return _get(path, token)
    except urllib.error.HTTPError as e:
        if e.code in (404, 409):
            return None
        raise RuntimeError(f"GitHub API {path}: HTTP {e.code}") from e


def _ground_truth(org: str, repo: str, branch: str, token: str):
    quoted = urllib.parse.quote(branch, safe="")
    data = _get_or_none(
        f"/repos/{org}/{repo}/contents/GROUND_TRUTH.md?ref={quoted}",
        token)
    if data is None:
        return None
    content = data.get("content")
    if data.get("encoding") == "base64" and content:
        return base64.b64decode(content).decode("utf-8", "replace")
    if data.get("download_url"):
        req = urllib.request.Request(
            data["download_url"],
            headers={"Authorization": f"Bearer {token}",
                     "User-Agent": "savage-standard-estate-fetch"})
        with urllib.request.urlopen(req) as resp:
            return resp.read().decode("utf-8", "replace")
    return None


def _ci_runs(org: str, repo: str, branch: str, token: str):
    quoted = urllib.parse.quote(branch, safe="")
    data = _get_or_none(
        f"/repos/{org}/{repo}/actions/runs?branch={quoted}&per_page=5",
        token)
    if not data:
        return []
    return [{"workflow": run.get("name"),
             "status": run.get("status"),
             "conclusion": run.get("conclusion"),
             "updated_at": run.get("updated_at")}
            for run in data.get("workflow_runs", [])[:5]]


def fetch_snapshot(org: str, token: str) -> dict:
    """Collect the estate snapshot for ``org``. Raises RuntimeError on
    API failures other than a repo's missing GROUND_TRUTH.md / runs."""
    if not token:
        raise ValueError("a GitHub token is required")
    repos = []
    page = 1
    while True:
        batch = _get(
            f"/orgs/{org}/repos?per_page=100&page={page}&type=all",
            token)
        if not isinstance(batch, list):
            raise RuntimeError(f"GitHub API /orgs/{org}/repos: "
                               f"unexpected response")
        repos.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    entries = []
    for repo in sorted(repos, key=lambda r: r.get("name") or ""):
        name = repo["name"]
        branch = repo.get("default_branch") or "main"
        ref = _get_or_none(
            f"/repos/{org}/{name}/git/ref/heads/"
            f"{urllib.parse.quote(branch, safe='')}", token)
        head = (ref or {}).get("object", {}).get("sha")
        if not head:
            raise RuntimeError(
                f"GitHub API: no head for {org}/{name}@{branch}")
        entries.append({
            "name": name,
            "head": head,
            "ground_truth": _ground_truth(org, name, branch, token),
            "ci": _ci_runs(org, name, branch, token),
        })
    taken_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"org": org, "taken_at": taken_at, "repos": entries}
