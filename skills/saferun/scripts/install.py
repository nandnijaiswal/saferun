#!/usr/bin/env python3
"""
Manual install (without the plugin system): copy the skill into Claude Code's skills folder and register Jev as a
PreToolUse hook. Prefer the one-line plugin install from the README; do not use both, or the hook runs twice.

  python scripts/install.py                      # user-wide (~/.claude)
  python scripts/install.py --scope project      # this repo only (./.claude)
  python scripts/install.py --dry-run            # show what would change
  python scripts/install.py --uninstall          # remove the hook (keeps the skill files)

Existing settings are merged, never overwritten, and a timestamped backup is written first.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

SKILL_SRC = Path(__file__).resolve().parent.parent
MATCHER = "Bash|PowerShell|Write|Edit|MultiEdit|NotebookEdit|Read|mcp__.*"
MARKER = "jev.py\" hook"


def is_ours(hook_group: dict) -> bool:
    return any(MARKER in str(h.get("command", "")) for h in hook_group.get("hooks", []))


def main() -> int:
    ap = argparse.ArgumentParser(description="Install the SafeRun skill + Jev PreToolUse hook for Claude Code.")
    ap.add_argument("--scope", choices=["user", "project"], default="user")
    ap.add_argument("--project-dir", default=".", help="project root for --scope project")
    ap.add_argument("--uninstall", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-copy", action="store_true", help="register the hook against this folder instead of copying the skill")
    args = ap.parse_args()

    base = Path.home() / ".claude" if args.scope == "user" else Path(args.project_dir).resolve() / ".claude"
    settings_path = base / "settings.json"
    dest = SKILL_SRC if args.no_copy else base / "skills" / "saferun"

    settings = {}
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text(encoding="utf-8") or "{}")
        except ValueError:
            print(f"! {settings_path} is not valid JSON; fix it first.")
            return 1

    pre = settings.setdefault("hooks", {}).setdefault("PreToolUse", [])
    before = len(pre)
    pre[:] = [g for g in pre if not is_ours(g)]

    if not args.uninstall:
        cmd = f'"{Path(sys.executable).as_posix()}" "{(dest / "scripts" / "jev.py").as_posix()}" hook'
        pre.append({"matcher": MATCHER, "hooks": [{"type": "command", "command": cmd, "timeout": 15}]})
    if not pre:
        settings["hooks"].pop("PreToolUse")
    if not settings["hooks"]:
        settings.pop("hooks")

    action = "Uninstall" if args.uninstall else "Install"
    print(f"{action} SafeRun ({args.scope} scope)")
    if not args.uninstall:
        print(f"  skill  -> {dest}{'  (in place)' if args.no_copy else ''}")
    print(f"  hook   -> {settings_path}  ({'removed' if args.uninstall else 'PreToolUse: ' + MATCHER})")
    if args.dry_run:
        print("\n--dry-run: settings would become:\n" + json.dumps(settings, indent=2))
        return 0

    if not args.uninstall and not args.no_copy and dest.resolve() != SKILL_SRC:
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(SKILL_SRC, dest, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache"))

    settings_path.parent.mkdir(parents=True, exist_ok=True)
    if settings_path.exists():
        backup = settings_path.with_name(f"settings.json.saferun-backup-{time.strftime('%Y%m%d-%H%M%S')}")
        shutil.copy2(settings_path, backup)
        print(f"  backup -> {backup}")
    settings_path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")

    if args.uninstall:
        print(f"\nRemoved {before - len(pre)} SafeRun hook entr{'y' if before - len(pre) == 1 else 'ies'}. Restart Claude Code to apply.")
        return 0

    check = subprocess.run([sys.executable, str(dest / "scripts" / "jev.py"), "selftest"], capture_output=True, text=True)
    print("  check  -> " + (check.stdout.strip().splitlines() or ["?"])[-1])
    print("\nSafeRun is on. Restart Claude Code (or open /hooks) to load the hook.")
    print("Try it:  python \"%s\" demo" % (dest / "scripts" / "jev.py"))
    return 0 if check.returncode == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
