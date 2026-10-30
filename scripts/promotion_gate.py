#!/usr/bin/env python3
"""Validate a Hecate promotion bundle and enforce its conditional review gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, NoReturn

HUNT_RE = re.compile(r"^hunts/(\d{4})/(Q[1-4])/(H-\d{4,})\.md$")
QUERY_RE = re.compile(
    r"^queries/(H-\d{4,})/[^/]+\.(?:yml|yaml|kql|eql|leql|spl|cql|s1ql)$",
    re.IGNORECASE,
)
SIGMA_QUERY_RE = re.compile(r"\.ya?ml$", re.IGNORECASE)
NATIVE_QUERY_TARGETS = {
    ".kql": "sentinel_kql",
    ".eql": "elastic_eql",
    ".leql": "rapid7_leql",
    ".spl": "splunk_spl",
    ".cql": "crowdstrike_cql",
    ".s1ql": "sentinelone_s1ql",
}
RESEARCH_RE = re.compile(r"^research/(R-\d{4,})\.md$")
MANIFEST_RE = re.compile(r"^promotion-manifests/(H-\d{4,})-([a-f0-9]{12})\.json$")
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
)


def fail(message: str) -> NoReturn:
    print(message, file=sys.stderr)
    raise SystemExit(2)


def git_changed_paths(base_ref: str, head_ref: str) -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--name-only", "-z", f"{base_ref}...{head_ref}"],
        check=True,
        stdout=subprocess.PIPE,
    )
    return sorted(path.decode("utf-8") for path in result.stdout.split(b"\0") if path)


def frontmatter(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        fail(f"Hunt frontmatter is missing: {path}")
    try:
        end = next(i for i, line in enumerate(lines[1:], 1) if line.strip() == "---")
    except StopIteration:
        fail(f"Hunt frontmatter is not closed: {path}")
    values: dict[str, str] = {}
    for line in lines[1:end]:
        match = re.match(r"^(hunt_id|spawned_from):\s*['\"]?([^'\"]*)['\"]?\s*$", line)
        if match:
            values[match.group(1)] = match.group(2).strip()
    return values


def bundle_digest(files: dict[str, str]) -> str:
    digest = hashlib.sha256()
    for path, content in sorted(files.items()):
        digest.update(path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(content.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def inspect_bundle(base_ref: str, head_ref: str) -> dict[str, Any]:
    changed = git_changed_paths(base_ref, head_ref)
    control_paths = {
        "promotion-policy.yaml", ".github/workflows/promotion.yml",
        "scripts/promotion_gate.py", "tests/test_promotion_gate.py",
    }
    control_changes = control_paths.intersection(changed)
    if control_changes:
        if set(changed) - control_paths:
            fail("Promotion control changes must be submitted separately from content changes")
        return {
            "promotion": True,
            "policy_change": "promotion-policy.yaml" in control_changes,
            "control_change": True,
            "hunt_id": "",
            "manual_edits": True,
            "manifest_digest": None,
            "changed_paths": changed,
        }
    relevant_prefixes = ("hunts/", "queries/", "research/", "promotion-manifests/")
    if "promotion-policy.yaml" not in changed and not any(
        path.startswith(relevant_prefixes) for path in changed
    ):
        return {"promotion": False, "policy_change": False, "changed_paths": changed}
    if "promotion-policy.yaml" in changed:
        if changed != ["promotion-policy.yaml"]:
            fail("Promotion policy changes must be submitted separately from hunt bundles")
        return {
            "promotion": True,
            "policy_change": True,
            "hunt_id": "",
            "manual_edits": True,
            "manifest_digest": None,
            "changed_paths": changed,
        }
    hunts: list[tuple[str, str]] = []
    manifests: list[str] = []
    artifact_ids: set[str] = set()
    for path in changed:
        if match := HUNT_RE.fullmatch(path):
            hunts.append((match.group(3), path))
            artifact_ids.add(match.group(3))
        elif match := QUERY_RE.fullmatch(path):
            artifact_ids.add(match.group(1))
        elif match := RESEARCH_RE.fullmatch(path):
            continue
        elif MANIFEST_RE.fullmatch(path):
            manifests.append(path)
        else:
            fail(f"Changed path is outside the promotion allowlist: {path}")

    if len(hunts) != 1:
        fail(f"A promotion PR must change exactly one hunt file; found {len(hunts)}")
    hunt_id, hunt_path = hunts[0]
    if artifact_ids - {hunt_id}:
        fail("The PR contains query files for a different hunt")
    hunt_file = Path(hunt_path)
    if hunt_file.is_symlink() or not hunt_file.is_file():
        fail("Hunt file is missing or is a symlink")
    metadata = frontmatter(hunt_file)
    if metadata.get("hunt_id") != hunt_id:
        fail("Hunt frontmatter ID does not match its path")
    research_id = metadata.get("spawned_from")
    research_paths = [path for path in changed if RESEARCH_RE.fullmatch(path)]
    if research_id:
        if not re.fullmatch(r"R-\d{4,}", str(research_id)):
            fail("Hunt has an invalid spawned_from research ID")
        if any(RESEARCH_RE.fullmatch(path).group(1) != research_id for path in research_paths):
            fail("PR contains research that is not linked from this hunt")
    elif research_paths:
        fail("PR contains a research document not linked from its hunt")

    manual_edits = True
    manifest_digest: str | None = None
    manifest_path: str | None = None
    listed: list[str] = []
    if len(manifests) > 1:
        fail("A promotion PR must contain at most one manifest")
    if manifests:
        manifest_path = manifests[0]
        match = MANIFEST_RE.fullmatch(manifest_path)
        if not match or match.group(1) != hunt_id:
            fail("Promotion manifest does not match the hunt ID")
        if Path(manifest_path).is_symlink() or not Path(manifest_path).is_file():
            fail("Promotion manifest is missing or is a symlink")
        try:
            manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            fail(f"Could not read promotion manifest: {exc}")
        if manifest.get("schema_version") != 1 or manifest.get("publisher") != "hecate-runner":
            fail("Unsupported promotion manifest")
        if manifest.get("hunt_id") != hunt_id:
            fail("Promotion manifest hunt ID does not match")
        listed = manifest.get("files")
        if not isinstance(listed, list) or not all(isinstance(p, str) for p in listed):
            fail("Promotion manifest file list is invalid")
        if len(listed) != len(set(listed)):
            fail("Promotion manifest contains duplicate paths")
        listed_paths = set(listed)
        if hunt_path not in listed_paths:
            fail("Promotion manifest does not include the hunt file")
        manifest_files: dict[str, str] = {}
        for path in listed:
            if path == manifest_path:
                fail("Promotion manifest cannot list itself")
            if path == hunt_path:
                pass
            elif query_match := QUERY_RE.fullmatch(path):
                if query_match.group(1) != hunt_id:
                    fail(f"Promotion manifest lists a query for another hunt: {path}")
            elif research_match := RESEARCH_RE.fullmatch(path):
                if not research_id or research_match.group(1) != research_id:
                    fail(f"Promotion manifest lists research not linked from the hunt: {path}")
            else:
                fail(f"Promotion manifest lists a file outside this hunt bundle: {path}")
            candidate = Path(path)
            if candidate.is_symlink() or not candidate.is_file():
                fail(f"Bundle file is missing or is a symlink: {path}")
            content = candidate.read_text(encoding="utf-8")
            if path not in changed:
                try:
                    base_content = subprocess.run(
                        ["git", "show", f"{base_ref}:{path}"],
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    ).stdout.decode("utf-8")
                except (subprocess.CalledProcessError, UnicodeDecodeError):
                    fail(
                        "Manifest lists a file that is not present in the base branch: "
                        f"{path}"
                    )
                if base_content != content:
                    fail(
                        "Manifest lists a file that differs from the base but is absent "
                        f"from this PR: {path}"
                    )
            manifest_files[path] = content
        manifest_digest = str(manifest.get("sha256", ""))
        changed_bundle_paths = set(changed)
        changed_bundle_paths.discard(manifest_path)
        manual_edits = (
            not changed_bundle_paths.issubset(listed_paths)
            or bundle_digest(manifest_files) != manifest_digest
            or match.group(2) != manifest_digest[:12]
        )

    bundle_paths = set(listed)
    bundle_paths.update(path for path in changed if path != manifest_path)
    return {
        "promotion": True,
        "policy_change": False,
        "hunt_id": hunt_id,
        "hunt_path": hunt_path,
        "manual_edits": manual_edits,
        "manifest_digest": manifest_digest,
        "bundle_paths": sorted(bundle_paths),
        "changed_paths": changed,
    }


def validate_bundle(info: dict[str, Any]) -> None:
    import yaml

    paths = sorted(set(info["changed_paths"]) | set(info.get("bundle_paths", [])))
    for path in paths:
        candidate = Path(path)
        if candidate.is_symlink() or not candidate.is_file():
            fail(f"Bundle file is missing or is a symlink: {path}")
        text = candidate.read_text(encoding="utf-8")
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                fail(f"High-confidence credential material found in {path}")
        if QUERY_RE.fullmatch(path) and SIGMA_QUERY_RE.search(path):
            value = yaml.safe_load(text)
            if not isinstance(value, dict) or not {"title", "logsource", "detection"}.issubset(value):
                fail(f"Sigma rule is missing required fields: {path}")
            try:
                from sigma.collection import SigmaCollection

                SigmaCollection.from_yaml(text)
            except ImportError:
                fail("pySigma is not installed in the validation environment")
            except Exception as exc:
                fail(f"pySigma rejected {path}: {exc}")
        elif QUERY_RE.fullmatch(path):
            from hecate_agent.core.query_validator import QueryValidator

            target = NATIVE_QUERY_TARGETS[Path(path).suffix.lower()]
            result = QueryValidator().validate(target, text)
            if not result.is_valid:
                fail(f"Native {target} query validation failed for {path}: {result.error_messages}")


def set_output(values: dict[str, str]) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path:
        with open(output_path, "a", encoding="utf-8") as output:
            for key, value in values.items():
                output.write(f"{key}={value}\n")


def github_api(path: str) -> Any:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    repository = os.environ.get("GITHUB_REPOSITORY")
    if not token or not repository:
        fail("GitHub API context is unavailable for the conditional review check")
    separator = "&" if "?" in path else "?"
    values: list[Any] = []
    for page in range(1, 101):
        request = urllib.request.Request(
            f"https://api.github.com/repos/{repository}/{path}{separator}page={page}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                result = json.load(response)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            fail(f"GitHub review API request failed: {exc}")
        if not isinstance(result, list):
            if page == 1:
                return result
            fail("GitHub review API returned an unexpected response")
        values.extend(result)
        if len(result) < 100:
            break
    return values


def is_publisher_commit(commit: dict[str, Any], *, pull_author: str, publisher_login: str) -> bool:
    """Recognize App-authored commits even when GitHub cannot resolve author.login.

    GitHub's commit API can return a null ``author.login`` for App bot commits.
    In that case, require both the PR opener to be the configured App and the
    commit's author and committer emails to carry that App's exact noreply id.
    """
    author = commit.get("author") or {}
    login = str(author.get("login") or "").lower()
    if login:
        return login == publisher_login

    suffix = "[bot]"
    if not publisher_login.endswith(suffix):
        return False
    app_slug = publisher_login[: -len(suffix)]
    if pull_author not in {f"app/{app_slug}", publisher_login}:
        return False

    expected_email = re.compile(
        rf"\d+\+{re.escape(publisher_login)}@users\.noreply\.github\.com",
        re.IGNORECASE,
    )
    raw_commit = commit.get("commit") or {}
    raw_author = raw_commit.get("author") or {}
    raw_committer = raw_commit.get("committer") or {}
    author_email = str(raw_author.get("email") or "")
    committer_email = str(raw_committer.get("email") or "")
    return bool(
        expected_email.fullmatch(author_email)
        and expected_email.fullmatch(committer_email)
    )


def set_auto_merge(pull_request_node_id: str, *, enabled: bool, merge_method: str = "squash") -> None:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        fail("GitHub token is unavailable to enforce the current auto-merge policy")
    if enabled:
        mutation = """mutation EnablePromotionAutoMerge($pullRequestId: ID!, $mergeMethod: PullRequestMergeMethod!) {
          enablePullRequestAutoMerge(input: {pullRequestId: $pullRequestId, mergeMethod: $mergeMethod}) {
            pullRequest { number autoMergeRequest { mergeMethod } }
          }
        }"""
        variables = {"pullRequestId": pull_request_node_id, "mergeMethod": merge_method.upper()}
    else:
        mutation = """mutation DisablePromotionAutoMerge($pullRequestId: ID!) {
          disablePullRequestAutoMerge(input: {pullRequestId: $pullRequestId}) {
            pullRequest { number }
          }
        }"""
        variables = {"pullRequestId": pull_request_node_id}
    body = json.dumps(
        {
            "query": mutation,
            "variables": variables,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        "https://api.github.com/graphql",
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            result = json.load(response)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        fail(f"Could not disable auto-merge under the current policy: {exc}")
    if result.get("errors"):
        fail("Could not disable auto-merge under the current policy")


def enforce_review(decision_json: str, manual_edits: bool) -> None:
    import yaml

    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path:
        fail("GitHub pull request event is unavailable")
    event = json.loads(Path(event_path).read_text(encoding="utf-8"))
    pull = event.get("pull_request")
    if not isinstance(pull, dict):
        fail("This workflow event has no pull request")
    decision = json.loads(decision_json)
    base_sha = str((pull.get("base") or {}).get("sha", ""))
    policy_source = subprocess.run(
        ["git", "show", f"{base_sha}:promotion-policy.yaml"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout
    policy = yaml.safe_load(policy_source)
    review_policy = policy.get("review") or {}
    minimum = int(review_policy.get("minimum_approvals", 1))
    associations = set(review_policy.get("allowed_associations", ["OWNER", "MEMBER", "COLLABORATOR"]))
    publisher_login = str(policy.get("publisher_login", "hecate-publisher[bot]")).lower()
    auto_merge_policy = policy.get("auto_merge") or {}
    auto_merge_enabled = bool(auto_merge_policy.get("enabled"))
    current_pr = github_api(f"pulls/{pull['number']}")
    # A review submitted after merge still fires this workflow; the auto-merge
    # mutations reject closed PRs, and there is nothing left to gate.
    if current_pr.get("state") != "open":
        print(f"Pull request #{pull['number']} is {current_pr.get('state', 'not open')}; nothing to enforce.")
        return
    if not auto_merge_enabled and current_pr.get("auto_merge"):
        set_auto_merge(str(pull["node_id"]), enabled=False)

    # Any commit not authored by the configured GitHub App turns the PR into a
    # review-classified change, even if a person also updates its manifest.
    commits = github_api(f"pulls/{pull['number']}/commits?per_page=100")
    pull_author = str((current_pr.get("user") or {}).get("login") or "").lower()
    non_publisher_commit = any(
        not is_publisher_commit(
            commit,
            pull_author=pull_author,
            publisher_login=publisher_login,
        )
        for commit in commits
    )
    review_required = (
        bool(decision.get("review_required"))
        or manual_edits
        or non_publisher_commit
    )
    head_sha = str((pull.get("head") or {}).get("sha", ""))
    author = str((pull.get("user") or {}).get("login", "")).lower()
    reviews = github_api(f"pulls/{pull['number']}/reviews?per_page=100")
    latest: dict[str, dict[str, Any]] = {}
    changes_requested: set[str] = set()
    collaborator_permissions: dict[str, bool] = {}
    for review in sorted(reviews, key=lambda item: str(item.get("submitted_at", ""))):
        user = review.get("user") or {}
        login = str(user.get("login", "")).lower()
        association = str(review.get("author_association", "")).upper()
        if (
            not login
            or login == author
            or login.endswith("[bot]")
            or review.get("commit_id") != head_sha
            or not review.get("submitted_at")
            or review.get("state") not in {"APPROVED", "CHANGES_REQUESTED", "DISMISSED"}
        ):
            continue
        if association not in associations:
            # Public-repository installation tokens may see CONTRIBUTOR/NONE
            # for an organization member whose membership is private. Verify
            # repository authority instead of granting contributors approval.
            if "COLLABORATOR" not in associations:
                continue
            if login not in collaborator_permissions:
                authority = github_api(
                    f"collaborators/{urllib.parse.quote(login, safe='')}/permission"
                )
                collaborator_permissions[login] = authority.get("permission") in {
                    "admin", "maintain", "write",
                }
            if not collaborator_permissions[login]:
                continue
        if review.get("state") == "CHANGES_REQUESTED":
            changes_requested.add(login)
        elif review.get("state") in {"APPROVED", "DISMISSED"}:
            changes_requested.discard(login)
        previous = latest.get(login)
        if previous is None or str(review["submitted_at"]) > str(previous["submitted_at"]):
            latest[login] = review

    if changes_requested:
        fail("Promotion policy is waiting for requested changes to be resolved")
    if not review_required:
        if auto_merge_enabled and not current_pr.get("auto_merge"):
            set_auto_merge(
                str(pull["node_id"]),
                enabled=True,
                merge_method=str(auto_merge_policy.get("merge_method", "squash")),
            )
        print("Policy passed automatically; required repository checks control merge readiness.")
        return
    approvals = [review for review in latest.values() if review.get("state") == "APPROVED"]
    if len(approvals) < minimum:
        fail(
            f"Promotion policy requires {minimum} qualified approval(s) on the current commit "
            f"(found {len(approvals)})"
        )
    if auto_merge_enabled and not current_pr.get("auto_merge"):
        set_auto_merge(
            str(pull["node_id"]),
            enabled=True,
            merge_method=str(auto_merge_policy.get("merge_method", "squash")),
        )
    print(f"Promotion policy passed with {len(approvals)} current human approval(s).")


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    inspect_parser = subparsers.add_parser("inspect")
    inspect_parser.add_argument("--base-ref", required=True)
    inspect_parser.add_argument("--head-ref", required=True)
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("--base-ref", required=True)
    validate_parser.add_argument("--head-ref", required=True)
    review_parser = subparsers.add_parser("review")
    review_parser.add_argument("--decision", required=True)
    review_parser.add_argument("--manual-edits", choices=("true", "false"), required=True)
    subparsers.add_parser("validate-policy")
    args = parser.parse_args()

    if args.command == "review":
        enforce_review(args.decision, args.manual_edits == "true")
        return
    if args.command == "validate-policy":
        from hecate_runner.promotion_policy import load_policy

        load_policy(Path.cwd())
        print("Promotion policy is valid.")
        return
    info = inspect_bundle(args.base_ref, args.head_ref)
    if not info.get("promotion"):
        print(json.dumps(info, sort_keys=True))
        set_output(
            {"promotion": "false", "policy_change": "false", "control_change": "false"}
        )
        return
    if args.command == "validate":
        validate_bundle(info)
        print(f"Validated {len(info['changed_paths'])} allowlisted file(s) for {info['hunt_id']}.")
        return
    print(json.dumps(info, sort_keys=True))
    set_output(
        {
            "hunt_id": str(info["hunt_id"]),
            "manual_edits": str(info["manual_edits"]).lower(),
            "promotion": str(info["promotion"]).lower(),
            "policy_change": str(info["policy_change"]).lower(),
            "control_change": str(info.get("control_change", False)).lower(),
        }
    )


if __name__ == "__main__":
    main()
