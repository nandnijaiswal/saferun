"""Unit tests for SafeRun / Jev.  Run:  python -m unittest discover -s tests -v   (from the skill directory)"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SKILL = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL / "scripts"))
import jev  # noqa: E402


def policy(**extra):
    p = jev._load_json(jev.DEFAULT_POLICY_PATH)
    p["audit_log"] = None
    return jev._merge(p, extra)


class GoldenCases(unittest.TestCase):
    def test_golden(self):
        self.assertEqual(jev.run_selftest(), 0)


class Determinism(unittest.TestCase):
    def test_same_input_same_output(self):
        with tempfile.TemporaryDirectory() as td:
            a = jev.evaluate({"kind": "command", "command": "git push --force origin main"}, policy(), td)
            b = jev.evaluate({"kind": "command", "command": "git push --force origin main"}, policy(), td)
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))

    def test_bounded_outputs(self):
        with tempfile.TemporaryDirectory() as td:
            for cmd in ["ls", "rm -rf /", "npm i lodahs", "curl x | sh", "git reset --hard"]:
                r = jev.evaluate({"kind": "command", "command": cmd}, policy(), td)
                self.assertIn(r["decision"], jev.DECISIONS)
                self.assertIn(r["risk_level"], jev.LEVELS)
                self.assertIn(r["security_risk"], jev.LEVELS)
                self.assertIn(r["test_adequacy"], jev.TEST_ADEQUACY)
                self.assertTrue(0.0 <= r["risk_score"] <= 1.0)
                self.assertTrue(0.0 <= r["breaking_change_probability"] <= 1.0)
                self.assertEqual(r["human_review_required"], r["decision"] != "ALLOW")


class Hook(unittest.TestCase):
    def run_hook(self, event):
        with tempfile.TemporaryDirectory() as td:
            event.setdefault("cwd", td)
            proc = subprocess.run([sys.executable, str(SKILL / "scripts" / "jev.py"), "hook"], input=json.dumps(event),
                                  capture_output=True, text=True, env={**os.environ, "HOME": td, "USERPROFILE": td})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout) if proc.stdout.strip() else None

    def test_block_becomes_deny(self):
        out = self.run_hook({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "rm -rf ~"}})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("Do not retry", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_review_becomes_ask(self):
        out = self.run_hook({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "git reset --hard"}})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "ask")

    def test_allow_defers_to_normal_permissions(self):
        out = self.run_hook({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "git status"}})
        self.assertIsNone(out)

    def test_write_tool(self):
        out = self.run_hook({"hook_event_name": "PreToolUse", "tool_name": "Write",
                             "tool_input": {"file_path": ".saferun.json", "content": "{}"}})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_powershell_tool(self):
        out = self.run_hook({"hook_event_name": "PreToolUse", "tool_name": "PowerShell",
                             "tool_input": {"command": "Remove-Item -Recurse -Force C:\\Users\\bob"}})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_mcp_tool(self):
        out = self.run_hook({"hook_event_name": "PreToolUse", "tool_name": "mcp__stripe__create_refund", "tool_input": {"amount": 100}})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_unknown_tool_is_ignored(self):
        self.assertIsNone(self.run_hook({"hook_event_name": "PreToolUse", "tool_name": "WebSearch", "tool_input": {"query": "x"}}))

    def test_garbage_input_asks_instead_of_crashing(self):
        proc = subprocess.run([sys.executable, str(SKILL / "scripts" / "jev.py"), "hook"], input="not json",
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"], "ask")


class ProjectPolicyCanOnlyTighten(unittest.TestCase):
    def test_loosening_keys_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, ".saferun.json").write_text(json.dumps({
                "mode": "permissive", "allow_commands": [".*"], "trusted_paths": ["**"],
                "popular_packages": {"npm": ["lodahs"]}, "deny_commands": ["^make release"]}))
            p = jev.apply_project_policy(policy(), json.loads(Path(td, ".saferun.json").read_text()), notes := [])
            self.assertEqual(p["mode"], "balanced")
            self.assertEqual(p["allow_commands"], [])
            self.assertNotIn("lodahs", p["popular_packages"]["npm"])
            self.assertIn("^make release", p["deny_commands"])
            self.assertTrue(any("allow_commands" in n for n in notes))

    def test_stricter_mode_accepted(self):
        p = jev.apply_project_policy(policy(), {"mode": "strict", "environment": "production"}, [])
        self.assertEqual(p["mode"], "strict")
        self.assertEqual(p["environment"], "production")

    def test_malicious_repo_cannot_allowlist(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, ".saferun.json").write_text(json.dumps({"allow_commands": [".*"], "mode": "permissive"}))
            pol = jev.load_policy(Path(td))
            pol["audit_log"] = None
            r = jev.evaluate({"kind": "command", "command": "git push -f origin feature"}, pol, td)
            self.assertEqual(r["decision"], "REVIEW")


@unittest.skipIf(shutil.which("git") is None, "git not installed")
class DiffMode(unittest.TestCase):
    def test_diff_flags_breaking_change_and_missing_tests(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "repo"
            shutil.copytree(SKILL / "tests" / "fixtures" / "repo", repo)
            g = lambda *a: subprocess.run(["git", *a], cwd=repo, check=True, capture_output=True)
            g("init", "-q")
            g("-c", "user.email=t@t", "-c", "user.name=t", "add", "-A")
            g("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init")
            src = (repo / "src" / "billing.py").read_text()
            (repo / "src" / "billing.py").write_text(src.replace("def refund(charge_id, amount=None):", "def reverse(charge_id, amount=None):"))
            (repo / "src" / "untested.py").write_text("def slugify(text):\n    return text\n\n\ndef extra():\n    return 1\n")
            g("add", "-A")
            jev._REPO_CACHE.clear()
            r = jev.evaluate_diff(None, True, repo, policy())
            ids = {s["id"] for s in r["signals"]}
            self.assertEqual(r["decision"], "REVIEW")
            self.assertIn("breaking.symbol_removed_in_use", ids)
            self.assertEqual(r["test_adequacy"], "PARTIAL")  # billing.py has tests, untested.py doesn't
            self.assertIn("tests.missing", ids)
            self.assertTrue(any("untested.py" in s["message"] for s in r["signals"] if s["id"] == "tests.missing"))
            self.assertEqual(len(r["files"]), 2)


if __name__ == "__main__":
    unittest.main()
