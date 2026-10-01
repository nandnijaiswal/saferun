# SafeRun

### Every agent action, checked before it runs.

**SafeRun** is a safety and decision layer for AI coding agents, powered by **Jev**, a deterministic decision engine. Every shell command, file edit, dependency install, MCP tool call and deploy your agent attempts is checked *before* it executes:

| Verdict | What happens |
|---|---|
| ✅ **ALLOW** | runs normally |
| ⚠️ **REVIEW** | you approve it first |
| 🛑 **BLOCK** | it never runs, and Claude explains why and gives you the safe alternative |

> **Claude explains. Jev decides. SafeRun enforces.**

## Install (one line)

```bash
claude plugin marketplace add nandnijaiswal/saferun && claude plugin install saferun@saferun
```

Restart Claude Code and you're done. The skill and the enforcing hook are both switched on, and there are no settings files to edit. Requires Python 3.8+. On Windows it also needs Git for Windows, which Claude Code normally uses already.

Inside a Claude Code session you can do the same with `/plugin marketplace add nandnijaiswal/saferun`, then `/plugin install saferun@saferun`.

**Claude desktop app / claude.ai:** download `saferun-skill.zip` from the [latest release](https://github.com/nandnijaiswal/saferun/releases), then go to **Customize → Skills → + → Upload a skill**. Hooks don't exist there, so SafeRun runs in advisory mode: Claude checks risky actions with Jev before doing them.

---

```
$ python skills/saferun/scripts/jev.py demo

  SAFERUN — every agent action, checked before it runs.  (decisions by Jev)

  ALLOW   Read-only look around            No risk signals
  ALLOW   Clean build output               Deletes build artifacts (node_modules, dist, .next)
  BLOCK   Nuke from orbit                  Recursive delete of `~/` (root / home / system directory)
  BLOCK   The classic Steam bug            `rm -rf $STEAMROOT/*`: if the variable is empty this deletes from `/`
  BLOCK   Force-push to main               Force-pushes to protected branch `main` (rewrites shared history)
  REVIEW  Pipe the internet into bash      Pipes a script from the internet straight into an interpreter
  BLOCK   Exfiltrate the .env              Pipes secrets / environment variables into a network tool
  REVIEW  Install a typosquat              `reqeusts` looks like a typosquat of `requests`
  BLOCK   Install known malware            `crossenv` is a known malicious / hijacked package
  BLOCK   DROP TABLE in prod               Drops a table and every row in it [production]
  BLOCK   Hardcode an AWS key              Hardcoded AWS access key ID
  REVIEW  Skip the failing test            Disables / skips tests (or focuses with .only)
  BLOCK   Agent edits its own guardrails   Modifies SafeRun itself (an agent can't switch off its own safety layer)
  REVIEW  Ship it to prod                  Deploys / releases to a live environment
  BLOCK   MCP: buy a domain                Moves money / makes a purchase: `mcp__vercel__buy_domain`
  BLOCK   Terraform destroy                Destroys infrastructure managed by Terraform

  2 allowed · 4 sent for review · 10 blocked
```

## How it works

```
Claude wants to act ──► SafeRun hook (PreToolUse) ──► Jev scores the action
                                                        │
                    ┌───────────────────────────────────┼──────────────────────────────┐
                    ▼                                   ▼                              ▼
                 ALLOW                               REVIEW                          BLOCK
       normal permissions apply           permission prompt with            tool call denied; Claude
                                          Jev's reasoning                   explains + offers the safe path
```

- **Jev decides** (`skills/saferun/scripts/jev.py`). It is **bounded** (fixed enums, scores clamped to [0, 1]), **deterministic** (same action + policy gives the same verdict and the same `fingerprint`), and **fast** (~0.2 s, stdlib-only Python, no network).
- **Claude explains** (`skills/saferun/SKILL.md`). It turns the verdict into plain language: what the action would have done, why it matters, and the concrete safer command.
- **The hook enforces** (`hooks/hooks.json`). Verdicts are applied by Claude Code itself. The model can't skip the check.

Every verdict carries:

| field | values |
|---|---|
| `decision` | ALLOW / REVIEW / BLOCK |
| `risk_level` + `risk_score` | LOW…CRITICAL, 0–1 |
| `security_risk` | NONE…CRITICAL |
| `breaking_change_probability` | 0–1 |
| `test_adequacy` | ADEQUATE / PARTIAL / MISSING / WEAKENED / N/A |
| `human_review_required` | bool |
| `reversible` | bool |
| `signals[]` | concrete findings, each with evidence and a remediation |

## What it catches

- **Commands** (bash, PowerShell, cmd): catastrophic deletes (including `$VAR/` traps, `../..` resolving to home, PowerShell `Remove-Item`), force-pushes to protected branches, `reset --hard`, `clean -fdx`, SQL without `WHERE`, `DROP`, Terraform/Kubernetes/cloud deletes, `curl | sh`, base64-obfuscated execution, reverse shells, secret exfiltration, disabling TLS or OS security, `--no-verify`, `--dangerously-skip-permissions`. It sees through `bash -c`, `ssh host "…"`, `python -c`, heredocs, and shell strings embedded in code.
- **File edits**: hardcoded secrets (AWS, GitHub, Stripe, Anthropic, OpenAI, Slack, Google, JWT, DB URLs), shell and SQL injection, TLS-off, unsafe deserialization, XSS, CORS `*`, JWT `none`, CI/CD pipeline edits, migrations, auth code, lockfiles, writes outside the project or to `~/.ssh`.
- **Breaking changes**: removed or renamed functions are cross-referenced against your repo ("removes `refund`, still referenced in `src/api.py`"), along with signature changes, removed HTTP routes and dropped columns.
- **Tests**: skipped tests, `.only`, deleted assertions, `assert True`, CI muted with `|| true`, and whether touched code has tests at all.
- **Dependencies**: typosquats (`reqeusts`, `lodahs`, `expresss`), known-malicious and hijacked versions (`crossenv`, `event-stream@3.3.6`), git/URL installs, custom indexes, dependency confusion, and `postinstall` scripts.
- **MCP tools**: financial is BLOCK; delete / deploy / send are REVIEW; reads are ALLOW. Secrets in outgoing payloads are BLOCK.
- **Production**: `--prod`, `PROD_DATABASE_URL`, `--context prod-…` or `SAFERUN_ENV=production` raise destructive and data findings one severity level.

It doesn't nag. Plain `npm install`, `pytest`, `git commit`, `docker build`, `rm -rf node_modules` and API `curl`s are ALLOW, and ALLOW defers to Claude Code's normal permissions.

## Hard to talk out of

- **An agent can't switch off its own safety layer.** Edits to SafeRun's files or policy, and `claude plugin uninstall/disable saferun`, are hard-blocked.
- **A repo can make SafeRun stricter, never looser.** A cloned repo's `.saferun.json` can add deny rules or set `strict`, but its allow-lists are ignored.
- **Hard blocks beat allow-lists.** `rm -rf /` stays blocked even with `allow_commands: [".*"]`.
- **It fails safe.** If Jev errors, or Python is missing, the hook asks a human instead of allowing.

## Use it directly

```bash
python skills/saferun/scripts/jev.py cmd "git push --force origin main"          # pretty verdict card
python skills/saferun/scripts/jev.py eval --json '{"kind":"dependency","ecosystem":"pypi","packages":["reqeusts"]}'
python skills/saferun/scripts/jev.py diff --staged                               # review before commit
python skills/saferun/scripts/jev.py diff --base main --exit-code                # CI gate: exit 0/1/2
python skills/saferun/scripts/jev.py audit --stats                               # what has SafeRun caught?
```

**GitHub Actions:**
```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- run: python skills/saferun/scripts/jev.py diff --base origin/${{ github.base_ref }} --exit-code
```

## Policy

`~/.saferun/policy.json` is yours and has full power. `<repo>/.saferun.json` can only tighten.

```json
{
  "mode": "balanced",
  "protected_branches": ["main", "release/*"],
  "protected_paths": ["src/payments/**"],
  "deny_commands": ["^make deploy-prod"],
  "allow_commands": ["npm publish --dry-run"],
  "allow_packages": ["my-internal-lib"]
}
```

Modes are `strict`, `balanced` and `permissive`. The full reference is in [`skills/saferun/references/decision-schema.md`](skills/saferun/references/decision-schema.md).

## Develop

```bash
cd skills/saferun
python scripts/jev.py selftest                 # 122 golden decisions
python -m unittest discover -s tests -v        # + hook protocol, determinism, policy, git diff
python tools/build_skill_zip.py                # (from repo root) build dist/saferun-skill.zip
claude plugin validate .                       # (from repo root) validate the plugin + marketplace
```

## Honest limits

Jev is a fast rule engine, not a sandbox. It catches the common ways agents cause damage and refuses obvious workarounds, but a sufficiently novel action can still get past it. For real production credentials, also run agents in a container or least-privilege account. When Jev allows something, the honest phrasing is "no risk signals found", not "safe".

## Layout

```
.claude-plugin/plugin.json        # plugin manifest
.claude-plugin/marketplace.json   # makes this repo installable with one line
hooks/hooks.json                  # PreToolUse hook (auto-enabled by the plugin)
hooks/saferun-hook                # finds Python 3 and runs Jev
skills/saferun/SKILL.md           # how Claude uses Jev and explains verdicts
skills/saferun/scripts/jev.py     # the Jev engine + CLI + hook adapter
skills/saferun/policy/            # default policy, package seed lists
skills/saferun/references/        # decision schema, remediation playbook
skills/saferun/tests/             # golden cases, unit tests, fixture repo
tools/build_skill_zip.py          # builds the desktop/claude.ai upload zip
```

MIT licensed.
