# Jev decision schema

## Action (input)

Every action is a JSON object with a `kind`. The optional `context` is `{"cwd": "...", "environment": "production"}`.

| kind | fields |
|---|---|
| `command` | `command` (string), `shell` (`bash` \| `powershell`, default `bash`) |
| `file_write` | `path`, `content` (the full new file). Jev diffs it against the file on disk. |
| `file_edit` | `path`, plus either `old` + `new` (+ `replace_all`), or `edits: [{old, new, replace_all}]`. Jev applies the edits to the file on disk to get the full before/after. |
| `file_read` | `path` |
| `dependency` | `ecosystem` (`npm` \| `pypi` \| `cargo` \| `go` …), `packages` (specs such as `"lodash@4.17.21"` or `"requests==2.32.0"`) |
| `tool_call` | `tool` (e.g. `mcp__github__merge_pull_request`), `args` (object) |
| `deploy` | `target`, `environment` (`production` triggers the prod rules), optional `command` |

## Decision (output)

```jsonc
{
  "decision": "BLOCK",                 // ALLOW | REVIEW | BLOCK
  "risk_level": "CRITICAL",            // LOW | MEDIUM | HIGH | CRITICAL
  "risk_score": 0.95,                  // [0,1] noisy-OR of signal weights
  "security_risk": "NONE",             // NONE | LOW | MEDIUM | HIGH | CRITICAL
  "breaking_change_probability": 0.95, // [0,1]
  "test_adequacy": "N/A",              // ADEQUATE | PARTIAL | MISSING | WEAKENED | N/A
  "human_review_required": true,
  "reversible": false,
  "headline": "Force-pushes to protected branch `main` (rewrites shared history)",
  "action": {"kind": "command", "summary": "git push --force origin main"},
  "signals": [{
    "id": "vcs.force_push_protected", "category": "destructive", "severity": "critical", "weight": 0.95,
    "message": "...", "evidence": "...", "remediation": "...", "hard_block": true, "irreversible": true
  }],
  "hard_blocks": ["vcs.force_push_protected"],
  "production": false,
  "engine": {"name": "jev", "version": "1.0.0", "mode": "balanced", "policy_hash": "…", "thresholds": {"review": 0.3, "block": 0.9}},
  "fingerprint": "3f9c…",              // sha256(action + policy + engine version)[:16]
  "files": [ … ]                       // diff mode only: per-file decision, risk_level, top finding
}
```

## How the decision is made

1. Each analyzer emits **signals**. Each signal has a severity, which maps to a weight: info 0.03, low 0.12, medium 0.35, high 0.62, critical 0.95.
2. In **production** (`environment: production`, `SAFERUN_ENV=production`, or prod markers in the action such as `--prod`, `PROD_DATABASE_URL`, `--context prod-…`), destructive and data signals move up one severity level.
3. `risk_score = 1 − Π(1 − weight)`.
4. The verdict, in order:
   - any **hard** signal → **BLOCK** (no allow-list or mode can change this)
   - command matches the user's `allow_commands` (or tool matches `allow_tools`) → **ALLOW**
   - any **critical** signal, or `score ≥ block threshold` → **BLOCK**
   - `score ≥ review threshold` → **REVIEW**
   - otherwise → **ALLOW**
5. Thresholds by mode: `strict` review at 0.10 / block at 0.80; `balanced` 0.30 / 0.90; `permissive` 0.55 / 0.97.

So in `balanced` mode: one low signal is ALLOW, one medium is REVIEW, one high is REVIEW, two highs are still REVIEW (0.86), three highs are BLOCK, and any critical is BLOCK.

## Test adequacy

Computed over the files the action touches:
- **WEAKENED**: tests skipped (`.skip`, `@pytest.mark.skip`, `.only`), assertions removed, tautologies added (`assert True`), test files deleted, or the CI test step can no longer fail (`|| true`, `continue-on-error`)
- **ADEQUATE**: test files were changed or added alongside the code (and not weakened)
- **PARTIAL**: tests exist for the touched code but weren't updated (or only some files are covered)
- **MISSING**: no test file matches the touched code (`test_x.py`, `x.test.ts`, `x_test.go`, `XTest.java`…)
- **N/A**: no code was touched (docs, config, commands)

## Signal families

| prefix | covers |
|---|---|
| `destructive.*` | rm / Remove-Item / del, find -delete, shred, disk formatting, fork bombs, mass deletions, wiped files |
| `vcs.*` | force-push, protected-branch push, reset --hard, clean -fdx, history rewrites, branch deletion |
| `data.*` / `sql.*` / `nosql.*` / `db.*` | DROP / TRUNCATE / DELETE- or UPDATE-without-WHERE, DB resets, migrations, volume deletion |
| `infra.*` / `k8s.*` / `helm.*` / `aws.*` / `gcp.*` / `azure.*` / `docker.*` | IaC destroy/apply, cluster mutations, cloud deletes, privileged containers |
| `deploy.*` / `publish.*` | production deploys, registry publishes, releases, infra/deploy config edits |
| `rce.*` | curl \| sh, iex(iwr), base64 \| sh, reverse shells |
| `exfiltration.*` / `secrets.*` / `secret.*` | secret files sent over the network, env dumps, hardcoded keys (AWS, GitHub, Stripe, Anthropic, OpenAI, Slack, Google, JWT, DB URLs) |
| `supply_chain.*` | typosquats, known-malicious packages, git/URL installs, custom indexes, dependency confusion, lifecycle scripts, CI pipeline edits, lockfile edits |
| `vuln.*` | eval/exec, shell injection, SQL injection, TLS disabled, unsafe deserialization, XSS, CORS *, weak crypto, JWT none, auth/CSRF disabled |
| `breaking.*` | removed or renamed public symbols still in use, signature changes, removed HTTP routes, dropped columns |
| `tests.*` | skipped, deleted, weakened, missing tests |
| `privilege.*` / `security.*` / `persist.*` | sudo, setuid, system paths, shell rc files, scheduled tasks, registry, disabling OS security |
| `guardrail.*` | the agent touching SafeRun itself, Claude settings, git hooks, --no-verify, --dangerously-skip-permissions |
| `tool.*` | MCP calls classified by verb: financial, destructive, deploy, external (send/post), security, write, read |
| `policy.*` | user deny lists, protected paths |

## Policy keys

| key | default | who can set it |
|---|---|---|
| `mode` | `balanced` | user; a repo can only set something stricter |
| `thresholds` | see above | user; a repo can only lower them |
| `environment` | `dev` | user / `SAFERUN_ENV`; a repo can only set `production` |
| `auto_allow_safe` | `false` | user only. When `true`, LOW-risk ALLOWs skip Claude Code's permission prompt. |
| `fail_mode` | `ask` | what the hook does if Jev itself errors: `ask` / `deny` / `allow` |
| `audit_log` | `~/.saferun/audit.jsonl` | user only (`null` disables it). Summaries are redacted and file contents are never logged. |
| `protected_branches` | main, master, production, prod, release, release/*, trunk, live | merged |
| `protected_paths` | `[]` | merged. Globs relative to the repo; writes get REVIEW. |
| `trusted_paths` | temp dir, Claude memory and plans | user only. Writes here skip the outside-project check. |
| `allow_commands` / `allow_tools` | `[]` | user only. Regex full-match / glob. Never overrides hard blocks. |
| `deny_commands` / `deny_tools` | `[]` | merged; adds a hard BLOCK |
| `allow_packages` | `[]` | user only. Skips typosquat / unknown checks for these names. |
| `popular_packages` / `known_malicious` | curated seed lists | user extends; a repo can only add to `known_malicious` |

## Remote Jev (optional)

If the user sets `JEV_ENDPOINT` (and optionally `JEV_TOKEN`, `JEV_TIMEOUT`), the local verdict and the action are POSTed there as `{"action": …, "local_decision": …}`. The response must contain a `decision` from the enum. The **stricter** of local and remote wins: a remote service can escalate, never relax. If the endpoint is unreachable or returns an invalid response, Jev falls back to the local verdict and records `remote.status`. Note that this sends action contents, including file contents, to that endpoint.
