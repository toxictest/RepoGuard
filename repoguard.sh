#!/usr/bin/env bash
# RepoGuard v1.0.0 - defensive VCS metadata & commit history auditing.
# MIT License. Runtime: Bash 4.4+, git/curl (mode dependent), jq, core utilities.
set -euo pipefail
export LC_ALL=C
umask 077
VERSION=1.0.0
URL='' LIST='' REPO='' OUT=results/repoguard BASE=HEAD SCANNER=auto
THREADS=10 TIMEOUT=10 NO_COLOR=0 STRICT=0 TMP=''
RED='' YELLOW='' GREEN='' CYAN='' RESET=''
usage() {
    cat <<'EOF'
RepoGuard - Exposed .Git Directory & Commit History Auditor
Usage:
  ./repoguard.sh -u https://target.com [-o report_dir]
  ./repoguard.sh -l live_hosts.txt [-t 10] [--timeout 10]
  ./repoguard.sh -r /path/to/repo [--scanner auto|gitleaks|native] [--base HEAD]

Modes are exclusive: remote (-u and/or -l) OR local (-r).
  -u, --url URL        Website/base path or explicit /.git/HEAD URL
  -l, --list FILE      One HTTP(S) URL per line; # comments allowed
  -r, --repo PATH      Local repository (also bare repositories)
  -o, --output DIR     Report directory (default: results/repoguard)
  -t, --threads N      Parallel remote target workers (default 10, max 64)
      --timeout SEC   Per remote request (default 10, max 300)
      --scanner MODE  auto: gitleaks if available + native; else native
      --base REF      Compare unmerged refs against this commit (default HEAD)
      --strict        Exit 1 on exposure, secret finding or incomplete audit
      --no-color      Disable terminal ANSI colours
  -h, --help          Help

Outputs: git_audit_report.json, git_audit_summary.txt
Exit: 0 completed, 1 --strict findings, 2 usage/dependency/execution error.
Remote: small metadata GETs only; no Git object download, clone or reconstruction.
Local: no network; all locally reachable refs/commits; secret values never exported.
EOF
}
die() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }
info() { printf '%s%s%s\n' "$CYAN" "$*" "$RESET"; }
# shellcheck disable=SC2317
cleanup() { if [[ -n "$TMP" && -d "$TMP" ]]; then rm -rf -- "$TMP"; fi; }
trap cleanup EXIT
need_value() { [[ $# -ge 2 && -n "$2" && "$2" != -* ]] || die "Missing value for $1"; }
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -u|--url) need_value "$@"; URL=$2; shift 2;;
            -l|--list) need_value "$@"; LIST=$2; shift 2;;
            -r|--repo) need_value "$@"; REPO=$2; shift 2;;
            -o|--output) need_value "$@"; OUT=$2; shift 2;;
            -t|--threads) need_value "$@"; THREADS=$2; shift 2;;
            --timeout) need_value "$@"; TIMEOUT=$2; shift 2;;
            --base) need_value "$@"; BASE=$2; shift 2;;
            --scanner) need_value "$@"; SCANNER=$2; shift 2;;
            --strict) STRICT=1; shift;;
            --no-color) NO_COLOR=1; shift;;
            -h|--help) usage; exit 0;;
            *) usage >&2; die "Unknown option: $1";;
        esac
    done
    [[ -n "$URL$LIST$REPO" ]] || { usage >&2; die 'Select a mode'; }
    [[ -z "$REPO" || -z "$URL$LIST" ]] || die 'Remote and local modes cannot be combined'
    [[ "$SCANNER" == auto || "$SCANNER" == native || "$SCANNER" == gitleaks ]] || die 'Invalid scanner'
    [[ "$THREADS" =~ ^[0-9]{1,2}$ && "$TIMEOUT" =~ ^[0-9]{1,3}$ ]] || die 'Invalid numeric option'
    THREADS=$((10#$THREADS)); TIMEOUT=$((10#$TIMEOUT))
    [[ "$THREADS" -ge 1 && "$THREADS" -le 64 && "$TIMEOUT" -ge 1 && "$TIMEOUT" -le 300 ]] || die 'Threads 1-64; timeout 1-300'
    [[ -n "$OUT" && "$OUT" != / ]] || die 'Invalid output directory'
    if [[ "$NO_COLOR" -eq 0 && -t 1 ]]; then
        RED=$'\033[1;31m'; YELLOW=$'\033[1;33m'; GREEN=$'\033[1;32m'; CYAN=$'\033[1;36m'; RESET=$'\033[0m'
    fi
}
check_deps() {
    local tool missing=0 required='jq awk sed grep sort date mktemp mkdir rm cat wc tr cksum cmp cp mv'
    if [[ -n "$REPO" ]]; then required="$required git"; else required="$required curl"; fi
    for tool in $required; do
        if ! command -v "$tool" >/dev/null 2>&1; then printf 'Missing: %s\n' "$tool" >&2; missing=1; fi
    done
    if [[ "$missing" -eq 1 ]]; then
        printf 'Install (Debian/Ubuntu): sudo apt-get update && sudo apt-get install -y git curl jq gawk coreutils grep sed diffutils\n' >&2
        exit 2
    fi
    if [[ -n "$REPO" && "$SCANNER" != native ]] && ! command -v gitleaks >/dev/null 2>&1; then
        printf 'Gitleaks absent. Native fallback available. Install (Homebrew/Linuxbrew): brew install gitleaks\n' >&2
        printf 'Standalone binaries: https://github.com/gitleaks/gitleaks/releases\n' >&2
        [[ "$SCANNER" != gitleaks ]] || die 'Explicit gitleaks mode requires gitleaks'
    fi
}
# Reject credentials, queries, fragments and unsafe/ambiguous URL forms.
normalise_url() {
    local u=$1
    u=$(printf '%s' "$u" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    [[ -z "$u" || "$u" == \#* ]] && return 0
    [[ "$u" =~ ^https?://[^/?\#]+(/[^?\#]*)?$ ]] || return 2
    [[ "$u" != *[[:space:][:cntrl:]]* && "$u" != *'@'* && "$u" != *'\'* ]] || return 2
    u=${u%/}
    case "$u" in
        */.git/HEAD) u=${u%/.git/HEAD};;
        */.git/config) u=${u%/.git/config};;
        */.git) u=${u%/.git};;
        */.gitignore) u=${u%/.gitignore};;
        */.svn/entries) u=${u%/.svn/entries};;
    esac
    printf '%s\n' "$u"
}
# Explicit -q ignores user curlrc; no redirects, no insecure TLS, bounded body size.
request() {
    local method=$1 url=$2 body=$3 rc=0 code args=()
    [[ "$method" == HEAD ]] && args+=(--head)
    code=$(curl -q -sS --globoff --proto '=http,https' --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" \
        --max-filesize 1048576 --user-agent "RepoGuard/$VERSION" "${args[@]}" \
        --output "$body" --write-out '%{http_code}' --url "$url" 2>"$body.err") || rc=$?
    [[ "$code" =~ ^[0-9]{3}$ ]] || code=000
    printf '%s %s' "$code" "$rc"
}
remote_check() {
    local base=$1 idx=$2 dir="$TMP/remote-$2" path status rc hs _hr state severity reason verified body
    mkdir -p "$dir"
    local control_status control_rc
    read -r control_status control_rc < <(request GET "$base/.repoguard-missing-$(date +%s)-$RANDOM-$RANDOM" "$dir/control") || true
    : >"$dir/findings.ndjson"
    for path in /.git/HEAD /.git/config /.gitignore /.svn/entries; do
        body="$dir/body"
        read -r hs _hr < <(request HEAD "$base$path" "$dir/head") || true
        read -r status rc < <(request GET "$base$path" "$body") || true
        verified=false; severity=INFO; state=NOT_CONFIRMED; reason='Response does not contain verified VCS metadata'
        if [[ "$rc" -ne 0 ]]; then
            severity=WARN; state=INCONCLUSIVE; reason="Request failed or body exceeded 1 MiB (curl exit $rc)"
        elif [[ "$status" == 200 ]]; then
            if [[ "$control_status" == 200 && "$control_rc" -eq 0 ]] && cmp -s "$body" "$dir/control"; then
                state=SOFT_404; reason='Identical to random missing-path response; not confirmed'
            elif grep -aiEq '<!doctype html|<html([ >])|<body([ >])' "$body"; then
                state=NOT_CONFIRMED; reason='HTML response rejected (possible WAF, login or soft-404 page)'
            else
                case "$path" in
                    /.git/HEAD)
                        # A HEAD file is one short line; tolerate CRLF and detached HEAD hashes.
                        if [[ $(wc -c <"$body") -le 512 ]] && awk '
                            {sub(/\r$/, ""); if (NF) {n++; if ($0 ~ /^ref: refs\/heads\/[^[:space:]]+$/ || $0 ~ /^[0-9a-fA-F]+$/ && (length($0)==40 || length($0)==64)) ok++}}
                            END {exit !(n==1 && ok==1)}' "$body"; then verified=true; fi;;
                    /.git/config)
                        if grep -aqE '^\[core\][[:space:]\r]*$' "$body" &&
                           grep -aiqE '^[[:space:]]*(repositoryformatversion|bare)[[:space:]]*=[[:space:]]*(0|1|true|false)[[:space:]\r]*$' "$body"; then verified=true; fi;;
                    /.gitignore)
                        if [[ -s "$body" ]] && grep -aqE '^[[:space:]]*[^#[:space:]]+' "$body"; then
                            state=PUBLIC_IGNORE_FILE; reason='Non-HTML ignore-like text reachable; not proof of an exposed repository'
                        else state=EMPTY_OR_COMMENT_ONLY; reason='No usable ignore rules observed'; fi;;
                    /.svn/entries)
                        if grep -aqE '<wc-entries([[:space:]>]|$)' "$body" && grep -aqE '<entry([[:space:]>]|$)' "$body"; then verified=true
                        elif awk 'NR==1 {sub(/\r$/, ""); v=($0 ~ /^(8|9|10|12)$/)} NR<=8 && $0 ~ /^(dir|file)\r?$/ {k=1} END {exit !(v && k)}' "$body"; then verified=true; fi;;
                esac
                if [[ "$verified" == true ]]; then severity=FAIL; state=EXPOSED; reason='Publicly readable, content-verified VCS metadata'; fi
            fi
        elif [[ "$status" == 404 || "$status" == 410 ]]; then
            severity=PASS; state=NOT_FOUND; reason='Metadata not found at this path'
        elif [[ "$status" == 401 || "$status" == 403 ]]; then
            state=ACCESS_DENIED; reason='Access denied; repository existence not determined'
        elif [[ "$status" == 3* ]]; then
            severity=WARN; state=REDIRECT; reason='Redirect not followed; exposure not determined'
        else
            severity=WARN; state=INCONCLUSIVE; reason="Unexpected HTTP status $status"
        fi
        jq -nc --arg target "$base" --arg path "$path" --arg status "$status" --arg head "$hs" --arg severity "$severity" \
            --arg state "$state" --arg reason "$reason" --argjson verified "$verified" \
            '{module:"remote_metadata",target:$target,path:$path,http_status:$status,head_status:$head,severity:$severity,state:$state,verified:$verified,detail:$reason}' >>"$dir/findings.ndjson"
    done
    mv "$dir/findings.ndjson" "$TMP/remote-$idx.done"
}
run_remote() {
    MODE=remote; ENGINE=content-verification; : >"$TMP/targets"
    local ep line idx=0 running=0 pid
    local pids=()
    if [[ -n "$URL" ]]; then ep=$(normalise_url "$URL") || die 'Invalid URL'; [[ -n "$ep" ]] || die 'Empty URL'; printf '%s\n' "$ep" >>"$TMP/targets"; fi
    if [[ -n "$LIST" ]]; then
        [[ -r "$LIST" && -f "$LIST" ]] || die 'List file not readable'
        while IFS= read -r line || [[ -n "$line" ]]; do
            ep=$(normalise_url "$line") || die 'Invalid URL in list (use http:// or https://)'
            [[ -z "$ep" ]] || printf '%s\n' "$ep" >>"$TMP/targets"
        done <"$LIST"
    fi
    sort -u "$TMP/targets" >"$TMP/targets.sorted"
    [[ -s "$TMP/targets.sorted" ]] || die 'No endpoints'
    jq -Rn '[inputs]' <"$TMP/targets.sorted" >"$TMP/targets.json"
    info 'Remote mode: verifying small metadata responses; no repository download.'
    while IFS= read -r ep; do
        if [[ "$running" -ge "$THREADS" ]]; then wait -n || true; running=$((running-1)); fi
        idx=$((idx+1)); remote_check "$ep" "$idx" & pids+=("$!"); running=$((running+1))
    done <"$TMP/targets.sorted"
    for pid in "${pids[@]}"; do wait "$pid" || true; done
    local n
    for ((n=1;n<=idx;n++)); do
        if [[ -f "$TMP/remote-$n.done" ]]; then cat "$TMP/remote-$n.done" >>"$TMP/findings"
        else jq -nc --arg n "$n" '{module:"execution",severity:"WARN",state:"INCOMPLETE",detail:("Remote worker "+$n+" failed")}' >>"$TMP/findings"; fi
    done
}
# No fetch, replacement refs, hooks, external diffs or textconv in local scans.
local_git() {
    git --no-pager --no-replace-objects -C "$REPO" -c core.hooksPath=/dev/null -c core.fsmonitor=false \
        -c core.quotePath=false -c diff.external= "$@"
}
local_note() {
    jq -nc --arg severity "$1" --arg state "$2" --arg detail "$3" \
        '{module:"local_coverage",severity:$severity,state:$state,detail:$detail}' >>"$TMP/findings"
}
native_scan() {
    # Stream diffs straight into a redacting AWK parser; never persist raw patches.
    # Added AND removed lines: a secret deleted from HEAD still belongs to history.
    local_git log --all --full-history --root -m --no-renames --no-ext-diff --no-textconv \
        --format='@@REPOGUARD_COMMIT:%H' -p -- 2>"$TMP/git-errors" | awk '
        function q(s) {gsub(/\\/, "\\\\", s); gsub(/"/, "\\\"", s); gsub(/\t/, "\\t", s); gsub(/\r/, "\\r", s); return "\"" s "\""}
        function emit(rule, kind, line, key) {
            key=commit SUBSEP file SUBSEP rule SUBSEP line
            if (!seen[key]++) printf "{\"module\":\"history\",\"severity\":\"%s\",\"state\":\"%s\",\"rule\":%s,\"commit\":%s,\"file\":%s,\"line\":%d,\"scanner\":\"native\",\"detail\":\"Value omitted; review locally\"}\n", (kind=="SECRET"?"WARN":"INFO"), kind, q(rule),q(commit),q(file),line
        }
        /^@@REPOGUARD_COMMIT:/ {commit=substr($0,20); file=""; next}
        /^diff --git / {file=""; next}
        /^--- / {old=substr($0,5); sub(/^b\//,"",old);sub(/^a\//,"",old);next}
        /^\+\+\+ / {
            file=substr($0,5); if(file=="/dev/null")file=old; sub(/^b\//,"",file)
            lower=tolower(file)
            if(lower ~ /(^|\/)\.env([.\/]|$)/)emit("env-file-history","CONFIG_HISTORY",0)
            if(lower ~ /(^|\/)(staging|development)([.\/]|$)/ || lower ~ /[._-]staging[._-]/)emit("staging-config-history","CONFIG_HISTORY",0)
            next
        }
        /^@@ / {split($0,a," "); split(a[2],b,","); oldline=-b[1]; split(a[3],b,","); newline=b[1]+0; next}
        /^[+-]/ {
            if(file=="" || commit=="")next
            line=(substr($0,1,1)=="+"?newline++:oldline++)
            text=substr($0,2); low=tolower(text)
            if(text ~ /-----BEGIN (OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----/)emit("private-key","SECRET",line)
            if(low ~ /(postgres(ql)?|mysql|mongodb(\+srv)?|redis|mssql):\/\/[^[:space:]\/]+:[^[:space:]@]+@/)emit("database-credential-uri","SECRET",line)
            if(low ~ /(oauth[_-]?(secret|token)|client[_-]?secret|api[_-]?key|access[_-]?token|db[_-]?password|database[_-]?password)[[:space:]"\047]*[:=][[:space:]]*["\047]?[a-z0-9_+\/=.-]{8,}/)emit("credential-assignment","SECRET",line)
            next
        }
        /^ / {oldline++;newline++}
    ' >"$TMP/native.ndjson" || { local_note WARN INCOMPLETE 'Native history scan failed; repository may be partial or corrupt'; return; }
    cat "$TMP/native.ndjson" >>"$TMP/findings"
}
gitleaks_scan() {
    # Force built-in rules rather than silently trust an audited repos config/allowlist.
    printf '[extend]\nuseDefault = true\n' >"$TMP/gitleaks.toml"
    : >"$TMP/ignore"
    local rc=0
    ( cd "$TMP"; unset GITLEAKS_CONFIG GITLEAKS_CONFIG_TOML
      gitleaks git "$REPO" --config "$TMP/gitleaks.toml" --gitleaks-ignore-path "$TMP/ignore" \
        --ignore-gitleaks-allow --redact=100 --no-banner --no-color --report-format json \
        --report-path "$TMP/gitleaks.json" --exit-code 10 \
        --log-opts='--all --full-history --root -m --no-ext-diff --no-textconv' \
        >"$TMP/gitleaks-log" 2>&1 ) || rc=$?
    if [[ "$rc" != 0 && "$rc" != 10 ]]; then
        local_note WARN INCOMPLETE "Gitleaks failed (exit $rc); native results retained. Requires modern gitleaks git CLI."
        return
    fi
    if [[ ! -f "$TMP/gitleaks.json" ]] || ! jq -e 'type=="array"' "$TMP/gitleaks.json" >/dev/null 2>&1; then
        local_note WARN INCOMPLETE 'Gitleaks produced no valid JSON array; native results retained'; return
    fi
    # Allowlist metadata fields. Never export Secret, Match, author identity or commit messages.
    jq -c '.[] | {module:"history",severity:"WARN",state:"SECRET",scanner:"gitleaks",rule:(.RuleID//"unknown"),commit:(.Commit//""),file:(.File//""),line:(.StartLine//0),detail:"Value omitted; review locally"}' "$TMP/gitleaks.json" >>"$TMP/findings"
}
run_local() {
    MODE=local; ENGINE=native
    REPO=$(cd -- "$REPO" 2>/dev/null && pwd -P) || die 'Repository directory not found'
    # Prevent Git auto-fetch of promisor objects or any other network transport.
    export GIT_NO_LAZY_FETCH=1 GIT_ALLOW_PROTOCOL='' GIT_TERMINAL_PROMPT=0 GIT_NO_REPLACE_OBJECTS=1
    export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_OPTIONAL_LOCKS=0
    unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_EXTERNAL_DIFF GIT_CONFIG_PARAMETERS GIT_CONFIG_COUNT
    local_git rev-parse --git-dir >/dev/null 2>&1 || die 'Not a Git repository'
    jq -nc --arg repo "$REPO" '[$repo]' >"$TMP/targets.json"
    info 'Local mode: scanning locally reachable commit history; network transports disabled.'
    local count shallow base_oid
    count=$(local_git rev-list --all --count) || die 'Cannot enumerate commits'
    shallow=$(local_git rev-parse --is-shallow-repository)
    if [[ "$shallow" == true ]]; then local_note WARN INCOMPLETE 'Shallow clone: earlier history is not available; no fetch attempted'; fi
    if [[ "$count" -eq 0 ]]; then
        local_note INFO EMPTY_REPOSITORY 'No reachable commits; working tree and index are not scanned'
        return
    fi
    local_note INFO COVERAGE "$count reachable commit(s); all local refs, including locally cached remote refs. Reflog-only and unreachable objects excluded."
    native_scan
    if [[ "$SCANNER" != native ]] && command -v gitleaks >/dev/null 2>&1; then
        ENGINE=gitleaks+native; gitleaks_scan
    elif [[ "$SCANNER" == auto ]]; then
        local_note WARN LIMITED_SCANNER 'Gitleaks unavailable; native regex fallback is narrower and may miss provider-specific secrets'
    else
        local_note INFO LIMITED_SCANNER 'Native heuristic scanner selected; no exhaustive secret-detection guarantee'
    fi
    # Author emails are reduced to domains. An observed domain is not automatically internal.
    local_git log --all --format=%ae | awk -F@ 'NF>1 {d=tolower($NF);if(d ~ /^[a-z0-9][a-z0-9.-]*$/)print d}' | sort -u |
        jq -Rc '{module:"authors",severity:"INFO",state:"AUTHOR_DOMAIN",domain:.,detail:"Observed author email domain; internal/public status not inferred"}' >>"$TMP/findings"
    base_oid=$(local_git rev-parse --verify --end-of-options "$BASE^{commit}" 2>/dev/null) || die 'Invalid comparison base ref'
    local_git for-each-ref --no-merged="$base_oid" --format='%(refname)' refs/heads/ refs/remotes/ |
        jq -Rc --arg base "$BASE" '{module:"branches",severity:"INFO",state:"UNMERGED_REF",ref:.,base:$base,detail:"Not fully reachable from comparison base; may be stale cached remote ref"}' >>"$TMP/findings"
}
reports() {
    mkdir -p -- "$OUT" || die 'Cannot create output directory'
    jq -s --arg version "$VERSION" --arg mode "$MODE" --arg engine "$ENGINE" --arg date "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --slurpfile targets "$TMP/targets.json" '
        unique_by([.module,.target,.path,.scanner,.rule,.commit,.file,.line,.state,.domain,.ref,.detail]) as $f |
        {tool:"RepoGuard",version:$version,generated_at:$date,mode:$mode,scanner:$engine,targets:$targets[0],
         scope:(if $mode=="remote" then "Small metadata requests only; redirects not followed" else "Locally reachable commit diffs and refs; no network, no working-tree/index scan" end),
         secret_values_redacted:true,
         summary:{exposures:([$f[]|select(.state=="EXPOSED")]|length),
                  secret_findings:([$f[]|select(.state=="SECRET")]|length),
                  warnings:([$f[]|select(.severity=="WARN" and .state!="SECRET")]|length),
                  config_history:([$f[]|select(.state=="CONFIG_HISTORY")]|length),
                  unmerged_refs:([$f[]|select(.state=="UNMERGED_REF")]|length)},findings:$f} |
         .verdict=(if .summary.exposures>0 then "EXPOSED" elif .summary.secret_findings>0 then "SECRETS_FOUND" elif .summary.warnings>0 then "REVIEW" else "CLEAN_WITHIN_SCOPE" end)
        ' "$TMP/findings" >"$TMP/report.json"
    jq -r '
      "RepoGuard v\(.version) — \(.mode) audit",
      "Generated: \(.generated_at)", "Verdict: \(.verdict)", "Scanner: \(.scanner)",
      "Scope: \(.scope)", "Secret values: omitted", "",
      "Exposures: \(.summary.exposures) | Secret findings: \(.summary.secret_findings) | Coverage/review warnings: \(.summary.warnings)",
      "Configuration history: \(.summary.config_history) | Unmerged refs: \(.summary.unmerged_refs)", "",
      (.findings[] | "[\(.severity)] \(.module) / \(.state)  \(.target//.file//.domain//.ref//"")\(.path//"")  \(.rule//"")  \(.detail)",
       (if .commit then "    Commit: \(.commit)  Line: \(.line)  Scanner: \(.scanner)" else empty end))
    ' "$TMP/report.json" >"$TMP/summary.txt"
    # Remove terminal-control characters from displayable summaries (repo metadata is untrusted).
    tr -d '\000-\010\013\014\016-\037\177' <"$TMP/summary.txt" >"$OUT/git_audit_summary.txt"
    cp -- "$TMP/report.json" "$OUT/git_audit_report.json"
    local verdict color
    verdict=$(jq -r .verdict "$TMP/report.json")
    case "$verdict" in EXPOSED) color=$RED;; SECRETS_FOUND|REVIEW) color=$YELLOW;; *) color=$GREEN;; esac
    printf '\n%s%-22s%s\n' "$color" "$verdict" "$RESET"
    jq -r '.summary | "  Exposures: \(.exposures)   Secrets: \(.secret_findings)   Review: \(.warnings)\n  Config changes: \(.config_history)   Unmerged refs: \(.unmerged_refs)"' "$TMP/report.json"
    printf '  JSON: %s/git_audit_report.json\n  Text: %s/git_audit_summary.txt\n' "$OUT" "$OUT"
    if [[ "$STRICT" -eq 1 && "$verdict" != CLEAN_WITHIN_SCOPE ]]; then return 1; fi
}
main() {
    parse_args "$@"; check_deps
    TMP=$(mktemp -d "${TMPDIR:-/tmp}/repoguard.XXXXXX")
    : >"$TMP/findings"
    if [[ -n "$REPO" ]]; then run_local; else run_remote; fi
    reports
}
main "$@"
