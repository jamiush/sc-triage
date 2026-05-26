# Supply Chain Triage CLI (SCT) v2.1.0

**Mini Shai-Hulud Edition · TeamPCP · CVE-2026-45321**

A self-contained incident-response tool for quickly triaging developer machines and repositories during the May 2026 Mini Shai-Hulud supply chain attack. Runs on Linux/macOS (Bash) and Windows (PowerShell 5.1+) with no external dependencies beyond the shell and standard system tools.

---

## Background

In May 2026, threat actors compromised several open-source package maintainer accounts (CVE-2026-45321 / "Mini Shai-Hulud"). The campaign involved:

- **Malicious npm packages** injected into widely-used libraries (@tanstack router/start, @mistralai, @uipath, @opensearch-project, and many others), phoning home to `masscan.cloud`, `getsession.org`, `git-tanstack.com`, and `litter.catbox.moe`.
- **Self-propagating worm** — compromised install scripts drop persistence files (`router_runtime.js`, `setup.mjs`, `gh-token-monitor.sh/service`) and inject malicious Claude Code hooks and VS Code settings.
- **IDE extension tampering** — VS Code extensions modified between May 10–20 to exfiltrate credentials and tokens.
- **GitHub OAuth abuse** — attacker apps used to clone private repositories via stolen PATs. Commits self-authored as `voicproducoes` or `claude@users.noreply.github.com`; attacker injects `codeql_analysis.yml` into `.github/workflows/`.
- **Ransomware token threat** — the payload drops an npm token with the string `IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner` in `.npmrc`. Do **not** revoke this token without isolating the machine first.

SCT automates the triage checks every affected engineer and IR responder should run on their machine.

---

## Prerequisites

| Platform | Requirements |
|---|---|
| Linux / macOS | `bash` 4+, `git`, `python3` (for npm lockfile parsing), `ss` or `netstat` |
| Windows | PowerShell 5.1+, `git` in PATH |

No `npm install`, no virtual environment, no Docker image required.

---

## Quick Start

```bash
# Linux / macOS
chmod +x sct.sh
./sct.sh
```

```powershell
# Windows — run from PowerShell as your normal user (not Admin)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\sct.ps1
```

Both scripts launch an interactive menu. Press `1` for a Full Triage (recommended first run), answer the prompts, and review the summary at the end.

---

## Usage

### Interactive Mode (recommended)

Running the script with no arguments opens the menu. You will be prompted to:

1. Optionally add extra IOC domains/IPs beyond the defaults.
2. Optionally add extra secret-detection regexes.
3. Optionally add extra package names to flag.
4. Specify one or more project directories to scan (defaults to current directory).
5. Choose whether to save the output to a file.

### Direct CLI Mode — Bash

```bash
./sct.sh <command> [flags]

# Commands
all          Full triage: machine scan + dependency audit
machine      Machine scan only
deps         Dependency audit only
ide          IDE extension audit
platform     ADO / GitHub platform checklist
harden       Print hardening config snippets

# Flags
-i, --ioc          Add extra IOC domain or IP (repeatable)
-s, --secret       Add extra secret regex (repeatable)
-p, --package      Add extra package name (repeatable)
-d, --dir          Project directory to scan (repeatable; default: .)
-o, --output       Write report to file (auto-named if no value given)
-q, --quiet        No colour — pipe-friendly
-h, --help         Show help
```

**Examples**

```bash
# Triage two project dirs, save report
./sct.sh all -d ~/repos/frontend -d ~/repos/backend -o

# Machine scan only, extra IOC
./sct.sh machine -i evil.c2.io

# Quiet output for CI / log shipping
./sct.sh all -d /workspace -q | tee sct-$(hostname).txt

# Deps only, add an internal package to watch for
./sct.sh deps -p my-internal-lib -d /path/to/project
```

### Direct CLI Mode — PowerShell

```powershell
.\sct.ps1 <command> [flags]

# Same commands as Bash: all, machine, deps, ide, platform, harden

# Flags (named parameters)
-ExtraIOCs            @("evil.com","1.2.3.4")
-ExtraSecretPatterns  @("CORP_KEY_PATTERN")
-ExtraPackages        @("my-internal-lib")
-Dirs                 @("C:\repos\app1","C:\repos\app2")
-Output               "C:\reports\triage.txt"
-AutoOutput           (auto-name the output file)
-Quiet                (no colour)
-Help
```

**Examples**

```powershell
# Full triage, two repos
.\sct.ps1 all -Dirs "C:\repos\frontend","C:\repos\backend"

# Machine scan with extra IOC, auto-save
.\sct.ps1 machine -ExtraIOCs "evil.io","203.0.113.5" -AutoOutput

# Deps only, quiet (for CI)
.\sct.ps1 deps -Dirs "C:\workspace" -Quiet
```

### Non-interactive / CI Use

Pass a command directly and the script skips prompts. Exit code is `0` (all clear) or `1` (findings present), making it easy to gate pipelines:

```yaml
# GitHub Actions example
- name: SCT supply chain triage
  run: ./sct.sh all -d . -q
```

---

## Scan Modules

### Module 1 — Full Triage

Runs **Machine Scan** followed by **Dependency Audit** in one pass. This is the correct first step for any engineer who may have been affected. The combined summary shows findings from both modules.

---

### Module 2 — Machine Scan

Seven sequential checks on Linux/macOS, eight on Windows, for active compromise indicators on the local machine.

#### 2/1 · Network connections
Checks live TCP/UDP connections (`ss`/`netstat`) for any socket connected to a known-bad IP or hostname. An active connection is a **CRIT** — the machine should be isolated immediately.

**Value:** Catches malware that is currently phoning home. Fails fast — if this fires, escalation happens before anything else.

#### 2/2 · Hosts file and DNS resolution
Scans `/etc/hosts` (Linux/macOS) or `%SystemRoot%\System32\drivers\etc\hosts` (Windows) for non-standard entries that could redirect legitimate domains to attacker infrastructure. Also performs DNS resolution of all IOC hostnames — an IOC resolving is `[?]` informational (the domain is real), not a finding on its own.

**Value:** Detects DNS-hijacking persistence and confirms whether IOC domains are reachable from this network segment.

#### 2/3 · Shell / PowerShell history
Greps Bash, Zsh, Fish, and PowerShell history files for IOC strings. A match means the user ran a command that contacted or referenced attacker infrastructure.

**Value:** Reveals whether tooling (curl, npm, pip, git) directly pulled from attacker domains — even if those connections are no longer active.

#### 2/4 · Environment variables and credential files
Scans current environment variables and a curated list of credential files (`~/.aws/credentials`, `~/.npmrc`, `~/.docker/config.json`, `.env*`, etc.) for known secret patterns: AWS keys, GitHub PATs, JWTs, Stripe keys, database connection strings, and more (29 patterns by default).

**Value:** Identifies exposed secrets that an attacker could exfiltrate via a compromised package's postinstall script. These secrets need rotation even if no active compromise is confirmed.

#### 2/5 · Git history secret scan

Three sub-checks run per repository found in the configured scan directories:

| Sub-check | Command run | What it finds |
|---|---|---|
| Recent additions | `git log --all --since=2026-04-01 -p --diff-filter=AMR` | Secrets added to tracked files in or after April 2026 |
| All-time private keys | `git log --all -p --diff-filter=AMR` (full history) | PEM private key headers ever committed — regardless of date |
| IOC in commit messages | `git log --all --oneline --since=2026-04-01` | Commits whose message references an IOC hostname |

The exact commands are printed in dim text before they run so you can see precisely what is being executed.

**Monorepo support:** If a root directory is provided, SCT automatically discovers sub-packages with their own lockfiles up to 4 levels deep (excluding `node_modules`, `.git`, `vendor`) and scans git history from the repo root. npm v2/v3 lockfiles are parsed to detect workspace-hoisted and workspace-nested package entries.

**Value:** Finds secrets that were accidentally committed and later removed (they persist in git history). The all-time private-key check catches credentials from before the incident window.

#### 2/6 · Processes and scheduled tasks
Checks running processes for IOC strings in process name or command line. Also reports scheduled tasks outside the `\Microsoft\` namespace (Windows) and user crontabs (Linux/macOS) for review.

**Value:** Detects persistence mechanisms — a malicious process or scheduled task surviving reboots.

#### 2/7 · Malware artifact scan (Linux/macOS) · 2/8 (Windows)
Scans for known worm drop files and persistence mechanisms:

- **Payload files** — `router_init.js` and `tanstack_runner.js` anywhere under `$HOME` and scan directories (excluding `.cache`). Known SHA-256s are printed for confirmation.
- **Worm persistence files** — `~/.claude/router_runtime.js`, `~/.claude/setup.mjs`, `~/.vscode/setup.mjs`, `~/.local/bin/gh-token-monitor.sh`, and per-repo equivalents in `.claude/` and `.vscode/`.
- **Linux systemd persistence** — `~/.config/systemd/user/gh-token-monitor.service` and checks whether the service is currently active.
- **macOS LaunchAgent** — `~/Library/LaunchAgents/com.user.gh-token-monitor.plist`.
- **Worm config directory** — `~/.config/gh-token-monitor/`.
- **Attack-vector marker** — `@tanstack/setup` in `optionalDependencies` of any `package.json` in the scan path.
- **Ransomware token** — greps `.npmrc` for `IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner`; alerts to isolate before revoking.
- **Claude Code hooks** — warns if `~/.claude/hooks.json` or `~/.claude/hooks/` exists for manual verification.
- **Injected GitHub Actions workflow** — flags `codeql_analysis.yml` in `.github/workflows/` of any scanned repo.

**Value:** Directly detects the worm's known drop set, persistence mechanisms, and ransom markers — these are definitive compromise indicators requiring immediate isolation.

---

### Module 3 — Dependency Audit

Scans every configured project directory for the ~170 packages known to have been compromised in the Mini Shai-Hulud campaign across eight ecosystems:

| Ecosystem | File checked |
|---|---|
| npm | `package-lock.json` (v1, v2, v3) |
| pnpm | `pnpm-lock.yaml` |
| Yarn | `yarn.lock` |
| Python | `requirements.txt`, `Pipfile.lock`, `pyproject.toml`, `poetry.lock` |
| Rust/Cargo | `Cargo.lock` |
| Go | `go.mod`, `go.sum` |
| PHP/Composer | `composer.lock` |
| .NET/NuGet | `packages.lock.json`, `*.csproj` |

**Monorepo support:** When a root directory is provided, SCT automatically discovers any subdirectory containing a lockfile (up to 4 levels, skipping `node_modules`) and adds them to the scan list. The section header shows the expanded directory count.

**Value:** A package being present in a lockfile means it was or is installed. The lockfile check is definitive — it covers transitive (indirect) dependencies and avoids false positives from grepping source files.

---

### Module 4 — IDE Audit

Checks all detected IDEs for extensions or plugins with a last-write timestamp falling in the attack window of **May 10–20, 2026**, when malicious updates were pushed.

Checks: VS Code, VS Code Insiders, Cursor, Visual Studio, JetBrains (IntelliJ, WebStorm, PyCharm, GoLand, Rider), Sublime Text, Vim/Neovim, Eclipse, Atom.

Also saves a timestamped list of all installed VS Code extensions to `vscode-extensions-YYYYMMDD.txt` for manual review or comparison with a known-good baseline.

A universal checklist is printed at the end with manual steps for any IDE not auto-detected.

**Value:** IDE extensions run with full user privileges and have access to the filesystem, environment, and editor buffers. A tampered extension is as dangerous as a backdoored dependency.

---

### Module 5 — Platform Checklist

Prints a prioritised, actionable checklist for auditing the DevOps platforms your team uses:

- **Azure DevOps:** Org Audit Log (filter April 29 — today), PAT revocation, Service Connection review, Variable Group rotation, pipeline run history (May 10–20), outbound HTTPS to `getsession.org` or `git-tanstack.com` in pipeline logs.
- **GitHub:** Security Log review (OAuth events, PAT creation), PAT revocation (classic + fine-grained), Authorized OAuth App audit, Org Audit Log fork/PR filter, Actions secrets rotation. Also: search commits and PRs for author `voicproducoes` or `claude@users.noreply.github.com`; check for branches matching `dependabot/github_actions/format/*`; audit `.github/workflows/` for `codeql_analysis.yml` added after May 10.
- **Critical:** Do **not** revoke npm tokens before isolating the affected machine — the payload contains a destructive wipe triggered by token revocation.

Items are severity-tagged (CRITICAL / HIGH / MED). These steps cannot be automated — they require human review of audit logs.

**Value:** The GitHub breach was the attacker's initial access vector. Rotating PATs and reviewing OAuth grants closes the persistence path even if no local compromise is found.

---

### Module 6 — Hardening

Prints hardening configurations to copy into your projects and pipelines:

1. **`.npmrc`** — `ignore-scripts=true`, `audit=true`, `package-lock=true`. Prevents postinstall script execution, the primary exfiltration vector.
2. **`package.json` pnpm block** — `onlyBuiltDependencies`, `minimumReleaseAge`, `blockExoticSubdeps`.
3. **GitHub Actions SHA pinning** — before/after example and tooling reference (`pin-github-action`). Prevents tag-mutation attacks against CI actions.
4. **Pipeline install commands** — `npm ci --ignore-scripts`, `pnpm install --frozen-lockfile --ignore-scripts`, `pip install --no-deps`.
5. **DNS/firewall blocklist** — IOC domains and IPs to block at the network layer: `zero.masscan.cloud`, `api.masscan.cloud`, `94.154.172.43`, `filev2.getsession.org`, `seed1–3.getsession.org`, `git-tanstack.com`, `litter.catbox.moe`.

**Value:** Applies defence-in-depth so that even if a future package is compromised, postinstall scripts cannot exfiltrate data or make outbound connections.

---

## Understanding the Output

### Status prefixes

| Prefix | Colour | Meaning |
|---|---|---|
| `[OK]` | Green | Check passed — nothing found |
| `[!]` | Red | **Finding** — requires investigation or escalation |
| `[CRIT]` | Bold Red | **Critical finding** — active compromise indicator |
| `[?]` | Amber | Informational — notable but not a confirmed finding |
| `[--]` | Dim | Skipped — component not present on this machine |

### Summary block

At the end of each run a summary block shows:

- **Findings count** — the number of `[!]` and `[CRIT]` events. Directory-not-found errors, DNS resolutions, and informational notes do NOT count as findings.
- **Per-module status** — `CLEAN`, `FINDINGS:N`, `CHECKLIST`, or `DONE`.
- **Overall verdict** — `ALL CLEAR` or `ESCALATE IMMEDIATELY`.

### What counts as a finding

| Event | Status |
|---|---|
| Active TCP connection to IOC | CRIT / finding |
| IOC in shell or PS history | finding |
| Secret pattern in env / credential file | finding |
| Secret pattern in git history | finding |
| Private key material in git history | CRIT / finding |
| IOC in git commit message | finding |
| Compromised package in lockfile | finding |
| IDE extension modified in attack window | finding |
| Worm persistence file found (`router_runtime.js`, `setup.mjs`, etc.) | CRIT / finding |
| Ransomware npm token marker in `.npmrc` | CRIT / finding |
| `@tanstack/setup` in `optionalDependencies` | CRIT / finding |
| Injected `codeql_analysis.yml` in `.github/workflows/` | finding |
| Claude Code hooks present | informational only |
| IOC DNS resolves (domain is real) | informational only |
| Non-standard hosts entries | informational only |
| Scheduled tasks outside Microsoft namespace | informational only |
| Directory not found (input error) | informational only |

---

## Customisation

Add your own IOCs, secret patterns, or packages at any time:

```bash
# Bash: extra IOC, internal secret pattern, internal package
./sct.sh all \
  -i corp-c2.internal \
  -s "CORP_INTERNAL_KEY_[A-Z0-9]{32}" \
  -p my-internal-lib \
  -d /repos/myapp
```

```powershell
# PowerShell equivalent
.\sct.ps1 all `
  -ExtraIOCs "corp-c2.internal" `
  -ExtraSecretPatterns "CORP_INTERNAL_KEY_[A-Z0-9]{32}" `
  -ExtraPackages "my-internal-lib" `
  -Dirs "C:\repos\myapp"
```

Extra items are appended to the defaults — you cannot remove defaults from the CLI, but you can edit the `DEFAULT_IOCS`, `DEFAULT_SECRET_PATTERNS`, and `DEFAULT_PKGS` arrays at the top of each script.

---

## How the Modules Work Together

A complete triage has three layers:

```
  ┌─────────────────────────────────────────────────────┐
  │  Layer 1: Is this machine actively compromised?      │
  │  → Module 2: Machine Scan                            │
  │    Network connections, history, env, git, processes │
  └────────────────────┬────────────────────────────────┘
                       │ if CLEAN or escalated
  ┌────────────────────▼────────────────────────────────┐
  │  Layer 2: Was compromised code installed?            │
  │  → Module 3: Dependency Audit                        │
  │    Lockfile check across 8 ecosystems                │
  └────────────────────┬────────────────────────────────┘
                       │ regardless of result
  ┌────────────────────▼────────────────────────────────┐
  │  Layer 3: Was the attacker's entry path used here?   │
  │  → Module 4: IDE Audit                               │
  │  → Module 5: Platform Checklist                      │
  │    Extension tampering, GitHub OAuth, PATs            │
  └────────────────────┬────────────────────────────────┘
                       │ always
  ┌────────────────────▼────────────────────────────────┐
  │  Remediation: Harden to prevent re-infection         │
  │  → Module 6: Hardening                               │
  └─────────────────────────────────────────────────────┘
```

**All Clear** means: no active connections, no secrets exposed, no compromised packages installed, no tampered IDE extensions. Still apply hardening and rotate PATs preventatively.

**Any finding** means: isolate the machine from the corporate network, rotate all credentials that existed on the machine, open a DefectDojo (or equivalent) incident ticket, and escalate to the security team.

---

## Exit Codes (non-interactive / CLI mode)

| Code | Meaning |
|---|---|
| `0` | All clear — no findings |
| `1` | One or more findings — escalate |

---

## Files Written

| File | When created |
|---|---|
| `vscode-extensions-YYYYMMDD.txt` | IDE audit — full list of installed VS Code extensions |
| `sct-report-<hostname>-<timestamp>.txt` | When `-o` / `-AutoOutput` is used or user answers `y` to save prompt |
