#!/usr/bin/env python3
"""Build dist/saferun-skill.zip for uploading to the Claude desktop app / claude.ai (Customize > Skills > Upload a skill).

The zip holds the skill folder itself at its root (saferun/SKILL.md ...), which is what the upload expects.
Hooks don't exist outside Claude Code, so this package runs SafeRun in advisory mode.
"""
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILL = ROOT / "skills" / "saferun"
OUT = ROOT / "dist" / "saferun-skill.zip"
SKIP_PARTS = {"__pycache__", ".pytest_cache"}
SKIP_FILES = {"install.py"}  # Claude Code-only installer; meaningless in the app

OUT.parent.mkdir(exist_ok=True)
with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as z:
    for p in sorted(SKILL.rglob("*")):
        if p.is_dir() or SKIP_PARTS & set(p.parts) or p.name in SKIP_FILES or p.suffix == ".pyc":
            continue
        z.write(p, Path("saferun") / p.relative_to(SKILL))
print(f"wrote {OUT.relative_to(ROOT)} ({OUT.stat().st_size // 1024} KB)")
