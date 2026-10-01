---
name: saferun
description: SafeRun is a safety and decision layer for AI coding agents, powered by Jev, a deterministic decision engine. Before an agent runs a risky shell command, writes or edits code, installs a dependency, calls an MCP tool, or deploys, Jev scores the action and returns a bounded verdict (ALLOW / REVIEW / BLOCK) with risk level, security risk, breaking-change probability, test adequacy and whether a human must review. Claude then explains the verdict and proposes the safer fix. Use this skill whenever an action could be destructive or irreversible (rm -rf, force-push, reset --hard, DROP/DELETE/TRUNCATE, terraform destroy, kubectl delete, deploys, publishing), touches secrets or credentials, installs packages, edits CI/auth/migrations, or calls a tool that sends, deletes, deploys or pays. Also use it when the user asks "is this safe", "should I run this", "check this command", "review my diff before I commit / open a PR / deploy", "guard my agent", "put guardrails on Claude", or "set up SafeRun"; when a SafeRun hook message (BLOCK or REVIEW) appears and needs explaining; and when the user wants to tune SafeRun's policy.
---

# SafeRun: every agent action, checked before it runs

**Core principle: Claude explains, Jev decides, and SafeRun enforces.**

Jev is a deterministic, bounded decision engine (`scripts/jev.py`). It uses no LLM and no randomness. Every output is a fixed enum or a score in [0, 1], and the same action always gets the same verdict. Your job is to **turn Jev's verdict into clear language and a safer path forward**. You never re-score an action, argue with the verdict, or quietly override it.

```
agent wants to act ──► Jev scores it ──► ALLOW   ─► proceed
                                    ├──► REVIEW  ─► stop, show the card, ask the human
                                    └──► BLOCK   ─► don't run it; explain + offer the safe alternative
```

All paths below are relative to this skill's base directory.

---

## 1. Two ways SafeRun runs

**A. Enforced, via the hook (preferred).** When SafeRun is installed as a Claude Code plugin, the hook is switched on automatically, and Jev runs as a Claude Code `PreToolUse` hook on `Bash`, `PowerShell`, `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, `Read` and every `mcp__*` tool:

- ALLOW: no output, so Claude Code's normal permission flow applies
- REVIEW: `ask`, so the user sees a permission prompt with Jev's reasoning
- BLOCK: `deny`, so the tool call never runs and you receive Jev's reason

If you see a message starting with `🛑 SafeRun (Jev) verdict: BLOCK` or `⚠️ ... REVIEW`, that is this skill. Go to section 4.

**B. Advisory, by calling Jev yourself.** Use this when the hook isn't installed, or when the user asks you to check something:

```bash
python scripts/jev.py cmd "<shell command>" --json                   # one command (add --shell powershell on Windows PS)
python scripts/jev.py eval --json '<Action JSON>'                    # file edit / dependency / tool call / deploy
python scripts/jev.py eval --file <action.json>                      # same, for large payloads (write the JSON to scratch first)
python scripts/jev.py diff --staged --json                           # review staged changes before a commit
python scripts/jev.py diff --base main --json                        # review a branch before a PR
```

The Action JSON shapes are in `references/decision-schema.md`. The most common ones:

```json
{"kind": "command",    "command": "git push --force origin main", "shell": "bash"}
{"kind": "file_edit",  "path": "src/billing.py", "old": "def refund(", "new": "def reverse("}
{"kind": "file_write", "path": "src/config.py", "content": "..."}
{"kind": "dependency", "ecosystem": "npm", "packages": ["expresss"]}
{"kind": "tool_call",  "tool": "mcp__stripe__create_refund", "args": {"amount": 5000}}
{"kind": "deploy",     "target": "api", "environment": "production"}
```

In advisory mode, **evaluate before you execute** any action matching the triggers in the description. Batch the checks if you're about to run several risky steps. Don't evaluate obviously read-only actions (`ls`, `git status`, reading normal source files): it wastes the user's time.

---

## 2. What Jev returns

| Field | Values | Meaning |
|---|---|---|
| `decision` | `ALLOW` / `REVIEW` / `BLOCK` | The verdict. This is binding. |
| `risk_level` | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` | Overall risk band |
| `risk_score` | 0.00–1.00 | Noisy-OR of all signal weights |
| `security_risk` | `NONE` … `CRITICAL` | Secrets, supply chain, exfiltration, privilege, guardrails |
| `breaking_change_probability` | 0.00–1.00 | Destructive, data, breaking-API or deploy risk |
| `test_adequacy` | `ADEQUATE` / `PARTIAL` / `MISSING` / `WEAKENED` / `N/A` | Do tests cover this change? Were tests disabled? |
| `human_review_required` | bool | `true` for REVIEW and BLOCK |
| `reversible` | bool | `false` if any signal is irreversible (deletes, publishes, payments…) |
| `signals[]` | id, category, severity, message, evidence, remediation | Why. Each one is a concrete, checkable finding |
| `fingerprint` | hex | Same action + same policy gives the same fingerprint (useful for audit) |

---

## 3. Obeying the verdict

| Verdict | What you do |
|---|---|
| **ALLOW** | Proceed. Mention Jev only if a signal is worth knowing (e.g. `tests.missing`); don't add ceremony. |
| **REVIEW** | **Stop before executing.** Show the SafeRun Card (section 5), name the specific risk, give the safer alternative, and ask the user to confirm. Proceed only on an explicit yes for *this* action. |
| **BLOCK** | **Do not execute it, and do not route around it.** Show the SafeRun Card, explain the danger in one or two plain sentences, and offer the safest way to reach the user's actual goal. If the user still insists, tell them to run it themselves or change their own policy (`~/.saferun/policy.json`). Never do either for them. |

### Never route around a BLOCK
A BLOCK covers the **effect**, not just the exact string. Do NOT:
- rephrase the command (`rm -rf ~` → `find ~ -delete` → `python -c "shutil.rmtree(...)"`)
- split it into steps, wrap it in a script you write and then run, or use a different tool or MCP server for the same effect
- edit `.saferun.json`, `~/.saferun/`, this skill's files, or `.claude/settings*.json` to weaken SafeRun (Jev blocks this too: an agent can't switch off its own safety layer)
- set `JEV_ENDPOINT` / `SAFERUN_*` variables, use `--no-verify`, or pass `--dangerously-skip-permissions`

The legitimate path forward is a **genuinely safer action** that Jev allows, or the human deciding.

---

## 4. Explaining a verdict (Claude's job)

Ground every sentence in Jev's `signals`. Don't invent risks Jev didn't report, and don't downplay ones it did. For each REVIEW or BLOCK:

1. **What it would do**, concretely: "This deletes your entire home directory, including SSH keys and every other project."
2. **Why that matters here**: irreversible? production? shared history? secrets leaving the machine?
3. **The safer path**, as a concrete command or code change, not a vague "be careful". Use the signal's `remediation` and `references/remediation-playbook.md`.
4. **What the human needs to decide**, for REVIEW.

Keep it short. People read SafeRun messages mid-flow.

---

## 5. The SafeRun Card (output format)

Use this whenever you report a REVIEW or BLOCK, or when the user explicitly asks for a check:

````markdown
### 🛑 BLOCK · risk CRITICAL (0.95)
`git push --force origin main`

| Security | Breaking | Tests | Human review | Reversible |
|---|---|---|---|---|
| NONE | 95% | N/A | required | **no** |

**Why:** Force-pushing `main` rewrites shared history. Teammates' commits on top of the old head disappear from the remote.

**Safer path:**
```bash
git push origin HEAD:refs/heads/fix/rebase-cleanup   # push to a new branch
gh pr create --fill                                  # and open a PR
```
````

Use 🛑 for BLOCK, ⚠️ for REVIEW and ✅ for ALLOW. For `diff` results, add a short per-file list from `files[]`, worst first.

---

## 6. Reviewing a diff before commit / PR / deploy

When the user says "review before I commit", "is this PR safe", or similar:

1. Run `python scripts/jev.py diff --staged --json` (or `--base main` for a branch).
2. Lead with the overall verdict, then the worst files.
3. Translate breaking-change signals into who breaks (`breaking.symbol_removed_in_use` lists the files that still call the symbol).
4. Treat `test_adequacy` of `MISSING` or `WEAKENED` as a call to action: offer to write the missing test or restore the skipped one.

---

## 7. Setup and tuning

**Install** (only when the user asks for it; it changes their Claude Code setup). The one-line plugin install puts the skill and the enforcing hook in place together:

```bash
claude plugin marketplace add nandnijaiswal/saferun && claude plugin install saferun@saferun
```

Without the plugin system, `python scripts/install.py` copies the skill and registers the hook in `settings.json` instead (`--scope project` for one repo, `--dry-run` to preview). Don't use both, or the hook runs twice.

The user must restart Claude Code afterwards. Only the user should uninstall or disable SafeRun; Jev blocks the agent from doing it.

In the Claude desktop app or claude.ai (uploaded as a zip), there are no hooks. SafeRun then works in advisory mode only (section 1B), and you must call Jev yourself before risky actions.

**Policy** (see `references/decision-schema.md` for every key):
- `~/.saferun/policy.json`: the user's own policy, with full power (mode, allow-lists, trusted paths…)
- `<repo>/.saferun.json`: a repo can only make SafeRun **stricter**: add deny rules, protected paths and branches, mode `strict`, or `environment: production`. Loosening keys from a repo are ignored, so a cloned repo can't allow-list itself.
- Modes: `strict` (any low risk gets REVIEW), `balanced` (default), `permissive`. Critical risk is a BLOCK in every mode, and hard blocks can't be allow-listed.
- `SAFERUN_ENV=production` in the user's environment makes destructive and data signals one level more severe.

**Other commands:** `python scripts/jev.py demo` (gallery of scary actions), `audit --stats` (what SafeRun has caught), `selftest` (golden cases).

---

## 8. Honesty about limits

Jev is a fast, deterministic rule engine, not a sandbox. It catches the common ways agents cause damage, but a novel enough action can get past it. When it matters (production credentials, real infrastructure), recommend also running the agent in a sandbox, container, or least-privilege account. Never tell the user an action is "safe" just because Jev allowed it. Say "Jev found no risk signals".
