"""Approval checks must use repository authority when membership is hidden."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/promotion_gate.py"
SPEC = importlib.util.spec_from_file_location("promotion_gate_test_target", SCRIPT)
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class ReviewGateTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        event = Path(directory.name) / "event.json"
        self.event = event
        self.pull = {
            "number": 2, "node_id": "PR_2", "state": "open",
            "head": {"sha": "current-head"}, "base": {"sha": "base"},
            "user": {"login": "hecate-publisher[bot]"}, "auto_merge": None,
        }
        event.write_text(json.dumps({"pull_request": self.pull}))
        self.policy = {
            "review": {"minimum_approvals": 1, "allowed_associations": ["OWNER", "MEMBER", "COLLABORATOR"]},
            "publisher_login": "hecate-publisher[bot]",
            "auto_merge": {"enabled": True, "merge_method": "squash"},
        }
        self.reviews = [self.review()]
        self.permission = "admin"
        self.lookup_failure = False
        self.permission_calls = []
        self.environment = patch.dict(os.environ, {"GITHUB_EVENT_PATH": str(event)})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        api = patch.object(gate, "github_api", side_effect=self.api)
        api.start()
        self.addCleanup(api.stop)
        merging = patch.object(gate, "set_auto_merge")
        self.auto_merge = merging.start()
        self.addCleanup(merging.stop)
        command = patch.object(
            gate.subprocess, "run",
            side_effect=lambda *args, **kwargs: SimpleNamespace(stdout=json.dumps(self.policy)),
        )
        command.start()
        self.addCleanup(command.stop)

    @staticmethod
    def review(**updates):
        result = {
            "user": {"login": "BrizoSec"}, "author_association": "CONTRIBUTOR",
            "commit_id": "current-head", "submitted_at": "2026-10-30T16:24:44Z",
            "state": "APPROVED",
        }
        result.update(updates)
        return result

    def api(self, path):
        if path == "pulls/2":
            return self.pull
        if path == "pulls/2/commits?per_page=100":
            return [{"author": {"login": "hecate-publisher[bot]"}}]
        if path == "pulls/2/reviews?per_page=100":
            return self.reviews
        if path.startswith("collaborators/"):
            self.permission_calls.append(path)
            if self.lookup_failure:
                raise SystemExit("repository authority lookup failed")
            return {"permission": self.permission}
        raise AssertionError(path)

    def enforce(self, *, manual_edits=False):
        self.event.write_text(json.dumps({"pull_request": self.pull}))
        gate.enforce_review(json.dumps({"review_required": True}), manual_edits)

    def assert_denied(self):
        with self.assertRaises(SystemExit):
            self.enforce()
        self.auto_merge.assert_not_called()

    def test_private_member_reported_as_contributor_with_admin_access(self):
        self.enforce()
        self.auto_merge.assert_called_once_with("PR_2", enabled=True, merge_method="squash")
        self.assertEqual(self.permission_calls, ["collaborators/brizosec/permission"])

    def test_writer_with_no_visible_association_can_approve(self):
        self.reviews = [self.review(author_association="NONE")]
        self.permission = "write"
        self.enforce()
        self.auto_merge.assert_called_once()

    def test_read_only_contributors_cannot_approve(self):
        for permission in ("read", "none", "triage"):
            with self.subTest(permission=permission):
                self.permission = permission
                self.assert_denied()

    def test_explicit_member_association_remains_supported(self):
        self.reviews = [self.review(author_association="MEMBER")]
        self.enforce()
        self.assertEqual(self.permission_calls, [])

    def test_owner_only_policy_does_not_gain_collaborator_fallback(self):
        self.policy["review"]["allowed_associations"] = ["OWNER"]
        self.assert_denied()
        self.assertEqual(self.permission_calls, [])

    def test_old_commit_approval_is_not_accepted(self):
        self.reviews = [self.review(commit_id="old-head")]
        self.assert_denied()
        self.assertEqual(self.permission_calls, [])

    def test_author_cannot_approve_own_pull_request(self):
        self.pull["user"] = {"login": "BrizoSec"}
        self.assert_denied()
        self.assertEqual(self.permission_calls, [])

    def test_bot_cannot_supply_human_approval(self):
        self.reviews = [self.review(user={"login": "other[bot]"})]
        self.assert_denied()
        self.assertEqual(self.permission_calls, [])

    def test_repeated_approval_is_counted_once(self):
        self.policy["review"]["minimum_approvals"] = 2
        self.reviews.append(self.review(submitted_at="2026-10-30T16:25:00Z"))
        self.assert_denied()
        self.assertEqual(len(self.permission_calls), 1)

    def test_requested_changes_still_block_approval(self):
        self.reviews.append(self.review(state="CHANGES_REQUESTED", submitted_at="2026-10-30T16:25:00Z"))
        self.assert_denied()

    def test_later_approval_resolves_requested_changes(self):
        self.reviews.insert(0, self.review(state="CHANGES_REQUESTED", submitted_at="2026-10-30T16:00:00Z"))
        self.enforce()
        self.auto_merge.assert_called_once()

    def test_comment_does_not_withdraw_approval(self):
        self.reviews.append(self.review(state="COMMENTED", submitted_at="2026-10-30T16:25:00Z"))
        self.enforce()
        self.auto_merge.assert_called_once()

    def test_dismissed_approval_does_not_count(self):
        self.reviews.append(self.review(state="DISMISSED", submitted_at="2026-10-30T16:25:00Z"))
        self.assert_denied()

    def test_failed_authority_lookup_never_enables_merge(self):
        self.lookup_failure = True
        self.assert_denied()

    def test_control_changes_still_require_qualified_approval(self):
        self.enforce(manual_edits=True)
        self.auto_merge.assert_called_once()

    def test_gate_tests_are_control_files(self):
        with patch.object(gate, "git_changed_paths", return_value=["scripts/promotion_gate.py", "tests/test_promotion_gate.py"]):
            result = gate.inspect_bundle("base", "head")
        self.assertTrue(result["control_change"])
        self.assertTrue(result["manual_edits"])

    def test_control_changes_cannot_include_hunt_artifacts(self):
        with patch.object(gate, "git_changed_paths", return_value=["scripts/promotion_gate.py", "hunts/2026/Q4/H-0001.md"]):
            with self.assertRaises(SystemExit):
                gate.inspect_bundle("base", "head")


if __name__ == "__main__":
    unittest.main()
