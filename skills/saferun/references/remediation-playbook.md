# Remediation playbook

What Claude should offer instead, by signal family. Always prefer a **concrete** command or code change that reaches the user's real goal.

## Deleting things (`destructive.rm_*`, `destructive.find_delete`, `vcs.clean*`)
- Name the exact folders: `rm -rf dist build .next` (build artifacts are ALLOW).
- Preview first: `find . -name '*.log' -print` / `git clean -n`, then delete the reviewed list.
- Move instead of deleting: `mkdir -p .trash && mv old_dir .trash/`.
- Shell variables: `rm -rf "${BUILD_DIR:?}/"` aborts if the variable is empty.
- PowerShell: `Remove-Item .\dist -Recurse -WhatIf` first.

## Git (`vcs.*`)
- Force-push to a protected branch: push to a new branch and open a PR: `git push origin HEAD:refs/heads/<topic>` then `gh pr create`.
- Force-push to your own branch: use `git push --force-with-lease`.
- `reset --hard` / `checkout .`: run `git stash push -u -m "before reset"` first and tell the user how to get it back (`git stash pop`).
- `--no-verify`: run the hook (`pre-commit run --all-files` / `npx lint-staged`) and fix what it reports.

## Databases (`sql.*`, `db.*`, `nosql.*`, `docker.volumes`)
- Run the matching `SELECT count(*) … WHERE …` first and show the number.
- Add a `WHERE` clause; wrap it in a transaction: `BEGIN; DELETE … WHERE …; -- check; COMMIT;`
- Dropping a table or column: expand/contract. Stop reading the column, deploy, then drop it in a later migration. Rename the table to `_deprecated_x` instead of dropping it.
- Back up first: `pg_dump -t users > users.sql`.
- Point destructive resets at a disposable local DB, never at `$PROD_*`.

## Infrastructure and deploys (`infra.*`, `k8s.*`, `deploy.*`, `publish.*`)
- Terraform: `terraform plan -out plan.tfplan`, show the plan, and let the human `apply plan.tfplan`.
- Kubernetes: `kubectl diff -f …`, `--dry-run=server`, and check `kubectl config current-context`.
- Deploys: deploy a preview (`vercel deploy`), share the URL, and let the human promote it.
- Publishing: `npm publish --dry-run` / `npm pack`, and let the maintainer publish.

## Remote code (`rce.*`)
- `curl … | bash` → `curl -fsSLo install.sh <url>`, show the user the script (or its checksum), then `bash install.sh`.
- Prefer the package manager: `brew install x`, `winget install x`, `npm i -D x`.

## Secrets (`secret.*`, `secrets.*`, `exfiltration.*`)
- Hardcoded key → `os.environ["API_KEY"]` / `process.env.API_KEY`, add it to `.env` (git-ignored) and `.env.example` (placeholder).
- If a real key was ever written to a tracked file or sent anywhere, tell the user to **rotate it**.
- Checking `.env` contents: `grep -c '^API_KEY=' .env` (proves presence without printing the value).
- Never send secret files to a network destination, even "just to debug".

## Dependencies (`supply_chain.*`)
- Typosquat: show the likely intended name (`requests`, not `reqeusts`) and link to the registry page.
- Known malicious: don't install it; find the legitimate package (`cross-env`, not `crossenv`).
- Git/URL install: pin a published version from the registry, or vendor and review the code.
- `--extra-index-url` → use `--index-url` for the private index only, or `--require-hashes`.
- Lifecycle scripts (`postinstall`): make them explicit commands (`npm run setup`).

## Code security (`vuln.*`)
- `shell=True` / `os.system` → `subprocess.run(["git", "log", path], check=True)`
- SQL f-strings → `cur.execute("SELECT … WHERE name = %s", (name,))`
- `verify=False` → `verify="/path/to/ca.pem"`
- `pickle.loads` on untrusted data → JSON; `yaml.load` → `yaml.safe_load`
- `innerHTML = x` → `textContent = x` or `DOMPurify.sanitize(x)`
- CORS `*` → an explicit origin list
- `eval(x)` → `JSON.parse(x)` / `ast.literal_eval(x)`

## Breaking changes (`breaking.*`)
- Removed symbol still in use: update every caller listed in the signal in the same change, or keep a deprecated alias: `refund = reverse  # deprecated`.
- Signature change: add the new parameter with a backwards-compatible default.
- Removed HTTP route: keep the old route as a redirect or deprecated handler, or version the API (`/v2/...`).

## Tests (`tests.*`)
- Skipped or weakened: fix the test or the code. If the test is genuinely obsolete, say so explicitly and let the user decide.
- Missing: offer to write the test, e.g. `tests/test_<module>.py` with one happy path and one edge case.
- CI `|| true`: quarantine the one flaky test by name instead of muting the whole suite.

## Guardrails (`guardrail.*`)
- There is no workaround to offer. Tell the user what you were trying to do, and that changing SafeRun is their call (`~/.saferun/policy.json`, `python scripts/install.py --uninstall`).

## MCP tools (`tool.*`)
- Financial: show the amount, payee and item, and ask the user to click the button themselves.
- External sends: show the exact message and recipients first.
- Destructive: name the exact resource ID and confirm it.
