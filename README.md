# RepoGuard v1.0.0

**Exposed .Git Directory & Commit History Auditor**  
Defensive Source Code & Version Control Auditing — free and open-source (MIT).

A standalone Bash auditor with two exclusive modes:

- **Remote:** content-verified checks for public VCS metadata. No clone, Git object download, repository reconstruction, or secret extraction from remote repositories.
- **Local:** scans locally available commit history for potential secrets, configuration history, author domains, and unmerged refs. No network access is requested; Git network transports and lazy fetch are disabled.

Use only on websites/repositories you own or are authorized to audit.

## Quick start

```bash
chmod +x repoguard.sh

# Single website (an explicit /.git/HEAD URL is also accepted)
./repoguard.sh -u https://target.com
./repoguard.sh -u https://target.com/.git/HEAD

# Day 1 live-host list
./repoguard.sh -l live_hosts.txt -t 10 -o results/repoguard

# Local history: Gitleaks when available, plus native checks
./repoguard.sh -r /path/to/repo

# Native-only / explicit Gitleaks mode
./repoguard.sh -r /path/to/repo --scanner native
./repoguard.sh -r /path/to/repo --scanner gitleaks --base main

# CI: nonzero for exposure, potential secrets, or incomplete coverage
./repoguard.sh -r /path/to/repo --strict
```

`-u` and `-l` can be combined and are deduplicated. `-r` cannot be combined with remote inputs. A list contains one full HTTP(S) URL per line; blank lines and `#` comments are ignored. Credentials, queries, fragments, whitespace/control characters, and non-HTTP protocols are rejected. Application base paths are retained: `https://site/app` tests `https://site/app/.git/HEAD` and related paths.

## Dependencies and installation

Runtime: **Bash 4.4+**, jq, awk, sed, grep, sort, date, mktemp, mkdir, rm, cat, wc, tr, cksum, cmp, cp, mv. Remote mode requires curl; local mode requires Git. No Python, Node, Go runtime, API keys or paid service is needed to run RepoGuard.

Missing core dependencies produce a clean exit and a single-line suggestion:

```bash
sudo apt-get update && sudo apt-get install -y git curl jq gawk coreutils grep sed diffutils
```

For Gitleaks, with Homebrew/Linuxbrew installed:

```bash
brew install gitleaks
```

Alternatively, install a standalone executable for your OS/architecture from [official Gitleaks releases](https://github.com/gitleaks/gitleaks/releases). Verify its published checksum before running it. RepoGuard never installs software automatically. Some Linux distribution packages are old and lack the modern `gitleaks git` interface.

The Gitleaks adapter was tested against **v8.30.1**. It requires the modern `git` subcommand and the options used by the script. An unsupported CLI or scanner failure is reported as **INCOMPLETE**, while native findings are retained.

| Scanner selection | Behavior |
|---|---|
| `auto` (default) | Gitleaks + native if installed; otherwise native with a limited-coverage warning and install suggestion |
| `gitleaks` | Requires Gitleaks; runs it plus native checks for configuration history and supplementary patterns |
| `native` | Explicitly selects the narrower built-in regex scan |

## Modules

### 1 — Exposed VCS metadata detector

For each base URL, checks:

| Path | Verification / interpretation |
|---|---|
| `/.git/HEAD` | A single short `ref: refs/heads/...` line, or a detached 40-/64-hex object ID |
| `/.git/config` | `[core]` plus a recognizable `repositoryformatversion` or `bare` assignment |
| `/.gitignore` | Reports reachable non-HTML, nonempty ignore-like text; **does not prove Git repository exposure** |
| `/.svn/entries` | Recognizable working-copy XML or a legacy entries version/directory structure |

Each check performs HEAD and then GET. HEAD alone never establishes exposure; GET still runs if a server rejects HEAD. HTTP 200 without matching content is not an exposure finding. HTML/WAF pages are rejected, and bodies identical to a randomized missing-path response are treated as soft-404s.

- Verified Git/SVN metadata → **EXPOSED / red**.
- 404/410 → not found at the tested path.
- 401/403 → access denied; existence remains unknown.
- Redirects, network/TLS errors, oversized responses or unexpected statuses → review/inconclusive.
- Redirects are **not followed**, and TLS certificate verification is not bypassed.
- Request bodies are bounded to **1 MiB** and each request has connection/total timeouts.

The random-path control and four HEAD+GET pairs total nine requests per base URL. Targets run in parallel; requests within a target run sequentially. These are heuristic metadata checks, not proof that the entire repository can be recovered. `.gitignore` has no uniquely identifying syntax, so an arbitrary plaintext response cannot be conclusively classified as a real ignore file.

### 2 — Commit-history secret scanner

Native scanning streams diffs from **all locally reachable refs**, including locally cached remote-tracking refs, root commits, and merge-parent diffs. Both added and removed lines are inspected, so deleting a secret from the latest revision does not hide it from the audit.

Native patterns include:

- OpenSSH, RSA, EC, DSA, generic and encrypted private-key markers.
- OAuth/client secrets, API/access tokens, and database-password assignments.
- Credential-bearing PostgreSQL/MySQL/MongoDB/Redis/MSSQL connection URIs.
- `.env` modifications and recognizable staging/development config paths.

Potential secrets are **WARN / yellow**, because matching a pattern does not prove a credential is real or active. `.env`/staging history is informational unless a secret pattern also matches. Native regexes are intentionally limited and can miss provider-specific, encoded, split, binary or unusual credentials; placeholders may generate false positives.

Gitleaks runs with built-in default rules explicitly selected, full redaction, and a dedicated empty ignore file. Repository-supplied `.gitleaks.toml`, `.gitleaksignore`, and inline `gitleaks:allow` comments do not silently suppress the audit. Only allowlisted finding metadata is retained: scanner/rule, file, commit and line. Raw matches, secret values, author names, author email addresses, and commit messages are not exported.

**History scope:** no working-tree or index scan; no reflog-only/unreachable objects, submodule histories, or external LFS content. Shallow history is flagged incomplete. A partial/corrupt clone may fail enumeration or produce an incomplete-scan warning; RepoGuard never fetches missing objects.

### 3 — Authors and branches

- Extracts distinct **author email domains**, not complete developer email addresses.
- Lists local and cached remote-tracking refs not fully reachable from `--base` (default `HEAD`).
- Does not presume that an observed domain is internal or that an unmerged branch is abandoned.
- Remote-tracking refs can be stale because no fetch is performed.

These checks are local-mode only. Remote mode deliberately does not obtain history to perform them.

## Options

| Option | Default | Purpose |
|---|---|---|
| `-u`, `--url` | — | Single remote base/metadata URL |
| `-l`, `--list` | — | File of remote URLs |
| `-r`, `--repo` | — | Local Git repository, including bare repos |
| `-o`, `--output` | `results/repoguard` | Report directory |
| `-t`, `--threads` | 10 | Remote target parallelism, 1–64 |
| `--timeout` | 10 | Seconds per remote request, 1–300 |
| `--scanner` | `auto` | `auto`, `gitleaks`, or `native` |
| `--base` | `HEAD` | Local branch comparison base |
| `--strict` | off | Exit 1 on exposure, potential secrets, or coverage/review warnings |
| `--no-color` | off | Disable ANSI terminal colours |
| `-h`, `--help` | — | Help |

Local scans have no hard overall time/commit limit; deep histories may take time. Request timeout and worker options apply to remote mode only.

## Output and privacy

```text
<report_dir>/
├── git_audit_report.json
└── git_audit_summary.txt
```

JSON contains version/time, mode/scanner, targets, scope, severity counts, verdict and structured findings. Remote findings include path, HEAD/GET status and content-verification state. Local findings include commit/file/line/rule metadata where relevant.

**Verdicts:**

- `EXPOSED` — red, verified remote VCS metadata.
- `SECRETS_FOUND` — yellow, potential history secrets.
- `REVIEW` — yellow, incomplete coverage or inconclusive remote requests.
- `CLEAN_WITHIN_SCOPE` — green, no exposure/secret/warning within the stated checks. Not a security guarantee.

Scanner records are counted, not unique credentials: the same secret may be reported by both engines or in multiple commits. Author/config/branch informational findings can coexist with a clean-within-scope verdict.

Secret **values from matches** are omitted. Metadata such as repository paths, filenames, commit IDs and domains is still sensitive; protect the reports. New files use restrictive permissions (`umask 077`); existing output files retain their existing permissions. Temporary responses/scanner output live in a private temporary directory and are removed on normal exit. No secret value verification or credential-use attempts occur.

Exit codes: **0** completed (findings may exist); **1** strict-mode findings/review; **2** usage/dependency errors. Unexpected I/O failures can return other nonzero codes. Reports overwrite the two named output files on subsequent runs.

## Testing

```bash
bash -n repoguard.sh
shellcheck -S warning repoguard.sh  # optional development utility
./tests/run_tests.sh

# Include a real installed Gitleaks binary in integration checks:
REPOGUARD_TEST_GITLEAKS="$(command -v gitleaks)" ./tests/run_tests.sh
```

Python 3 is used **only for the development test harness**, not the auditor. Fixtures use real temporary Git repositories, a controlled localhost HTTP server, and a Gitleaks adapter stub. The optional integration check uses the real standalone scanner.

Validated: **97 assertions passed, 0 failed**, including the real Gitleaks integration. Bash syntax and ShellCheck at warning severity are clean. Tests cover deleted-history secrets, key markers, database URIs, `.env`/staging configs, domains, unmerged branches, shallow/bare/empty repositories, redaction, WAF/soft-404 rejection, HEAD failures, detached HEADs, SVN, redirects, body limits, concurrent lists, invalid CLI input and strict exits.

To regenerate the fixture-based samples:

```bash
REPOGUARD_WRITE_SAMPLES=1 REPOGUARD_TEST_GITLEAKS="$(command -v gitleaks)" ./tests/run_tests.sh
```

Samples are controlled synthetic fixtures, **not findings against public websites**. See `sample-output/README.md`.

## If a finding is confirmed

Block public access to VCS metadata at the web server and remove repository internals from deployment artifacts. For a real leaked secret, revoke/rotate it first; deleting the latest file is insufficient. Review history rewriting, retained clones, caches and deployment logs under your organization's incident-response process. RepoGuard only reports findings and does not modify repositories or target servers.
