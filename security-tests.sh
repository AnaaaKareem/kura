#!/usr/bin/env bash
# security-tests.sh: run every security check used on Kura from one place.
#
#   ./security-tests.sh                 default group: static checks and the Django suite (unattended)
#   ./security-tests.sh --stack         also run the checks that need the Docker stack to be up
#   ./security-tests.sh --active        also run the active scanners (localhost only, noisy)
#   ./security-tests.sh --only NAME     run one step, for example --only ruff
#   ./security-tests.sh --list          list the steps and exit
#
# How it behaves:
#   - Each step writes its own log to docs/evidence/<date>/<number>_<step>.txt.
#   - A failing step never stops the run. A summary table is printed at the end.
#   - A step whose tool is missing is marked SKIP, not FAIL.
#   - The exit code is 1 if any step failed, otherwise 0.
#   - The scripts never run against anything except this machine (the active scanners
#     refuse any target that is not localhost) and never print secrets.
#
# Settings you can override through the environment:
#   PYTHON            Python to use (default: .venv/bin/python, then python3)
#   TEST_DB_PORT      port for the throwaway PostgreSQL 17 container (default: 55432)
#   ZAP_PASSWORD      demo account password, required by the ZAP step (see scripts/zap-baseline.sh)
#   ACTIVE_TARGET     host for the active scanners (default: localhost)
#   FFUF_WORDLIST     wordlist for ffuf
#   HYDRA_USER, HYDRA_WORDLIST   account and password list for the Hydra lockout test
#   SQLMAP_COOKIE     session cookie for the authenticated sqlmap run (never stored in the log)
set -uo pipefail

cd "$(dirname "$0")"

GROUPS_TO_RUN="default"
ONLY=""
LIST=0
while [ $# -gt 0 ]; do
    case "$1" in
        --stack) GROUPS_TO_RUN="$GROUPS_TO_RUN stack" ;;
        --active) GROUPS_TO_RUN="$GROUPS_TO_RUN active" ;;
        --only) ONLY="${2:-}"; shift ;;
        --list) LIST=1 ;;
        -h | --help) sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "Unknown option: $1 (try --help)" >&2; exit 2 ;;
    esac
    shift
done

DATE=$(date +%Y-%m-%d)
OUT="docs/evidence/$DATE"
PY="${PYTHON:-}"
[ -n "$PY" ] || { [ -x .venv/bin/python ] && PY=.venv/bin/python || PY=python3; }
VENV_BIN="$(dirname "$PY")"
TEST_DB_PORT="${TEST_DB_PORT:-55432}"
TEST_DB_NAME="kura-security-test-db"
ACTIVE_TARGET="${ACTIVE_TARGET:-localhost}"

mkdir -p "$OUT"
RESULTS=()
FAILED=0
COUNT=0

# Run one step. Arguments: name, group, function. Records PASS, FAIL or SKIP.
run_step() {
    local name="$1" group="$2" func="$3"
    case " $GROUPS_TO_RUN " in *" $group "*) ;; *) return 0 ;; esac
    if [ -n "$ONLY" ] && [ "$ONLY" != "$name" ]; then return 0; fi
    COUNT=$((COUNT + 1))
    local log
    log=$(printf '%s/%02d_%s.txt' "$OUT" "$COUNT" "$name")
    if [ "$LIST" = 1 ]; then printf '%-18s %s\n' "$name" "$group"; return 0; fi
    echo "[*] $name ($group)"
    local start=$SECONDS rc
    {
        echo "# $name | $(date -u +%Y-%m-%dT%H:%M:%SZ) | commit $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
    } > "$log"
    "$func" >> "$log" 2>&1
    rc=$?
    local status="PASS"
    if [ "$rc" = 77 ]; then status="SKIP"; elif [ "$rc" != 0 ]; then status="FAIL"; FAILED=$((FAILED + 1)); fi
    RESULTS+=("$(printf '%-18s %-8s %-6s %4ss  %s' "$name" "$group" "$status" "$((SECONDS - start))" "$log")")
}

# A step calls this when its tool or input is missing. It returns 77, which run_step reports as SKIP.
need() {
    command -v "$1" > /dev/null 2>&1 || [ -x "$VENV_BIN/$1" ] || { echo "SKIP: $1 is not installed"; return 77; }
}

# Environment used by Django commands (the same values AGENTS.md lists).
django_env() {
    export DEBUG=True VAULT_ENABLED=False VAULT_DATABASE_CREDENTIALS=False CLAMAV_REQUIRED=False
    export DATABASE_HOST=127.0.0.1 DATABASE_PORT="$TEST_DB_PORT" DATABASE_NAME=kura
    export DATABASE_USER=kura-admin DATABASE_PASSWORD=testpass DB_SSL_MODE=
    export SECRET_KEY=local-test-secret-key-not-for-production-min-50-chars-long
}

local_only_target() {
    case "$ACTIVE_TARGET" in localhost | 127.0.0.1 | ::1) return 0 ;; esac
    echo "Refusing to scan '$ACTIVE_TARGET'. The active scanners only run against localhost."
    return 1
}

# ---------- default group: unattended ----------

step_ruff() {
    need ruff || return $?
    "$VENV_BIN/ruff" check .
}

step_deploy_check() {
    # Production settings must pass Django's own deployment checks.
    DEBUG=False VAULT_ENABLED=False VAULT_DATABASE_CREDENTIALS=False CLAMAV_REQUIRED=False \
        SECURE_SSL_REDIRECT=True ALLOWED_HOSTS=localhost,127.0.0.1 \
        SECRET_KEY="$("$PY" -c 'import secrets; print(secrets.token_urlsafe(64))')" \
        "$PY" manage.py check --deploy
}

step_django_suite() {
    # Starts a throwaway PostgreSQL 17 (never the Compose database), runs every test module, removes it.
    need docker || return $?
    django_env
    docker rm -f "$TEST_DB_NAME" > /dev/null 2>&1
    docker run -d --name "$TEST_DB_NAME" -e POSTGRES_PASSWORD=testpass -e POSTGRES_USER=kura-admin \
        -e POSTGRES_DB=kura -p "127.0.0.1:$TEST_DB_PORT:5432" postgres:17-alpine > /dev/null || return 1
    sleep 8
    local rc=0
    # Pages link to hashed static files, so the manifest must exist before the tests run.
    if [ ! -f staticfiles/staticfiles.json ]; then
        "$PY" manage.py collectstatic --noinput --clear --ignore=admin --ignore=django_otp --ignore=otp_totp || rc=1
    fi
    if [ "$rc" = 0 ]; then
        "$PY" manage.py test kura kura.tests_security_leads_part1 kura.tests_security_leads_part2 \
            kura.tests_security_routes kura.tests_security_gaps kura.tests_signatures \
            kura.tests_owasp_regression kura.tests_final_gaps kura.tests_mfa_reset --noinput -v 2 2>&1 \
            | grep -vE '^time=' | sed -E 's/(session|csrf|token)[a-z_]*=[A-Za-z0-9_-]{16,}/\1=<redacted>/Ig'
        rc="${PIPESTATUS[0]}"
    fi
    docker rm -f "$TEST_DB_NAME" > /dev/null 2>&1
    return "$rc"
}

step_semgrep() {
    need semgrep || return $?
    "$VENV_BIN/semgrep" scan --config "p/django" --config "p/owasp-top-ten" --error
}

step_pip_audit() {
    need pip-audit || return $?
    # The same documented risk acceptances as .github/workflows/security.yml.
    "$VENV_BIN/pip-audit" -r requirements.lock.txt --strict \
        --ignore-vuln PYSEC-2026-4298 --ignore-vuln PYSEC-2026-1325
}

step_trivy_fs() {
    need trivy || return $?
    trivy fs . --scanners vuln --severity CRITICAL,HIGH --ignore-unfixed --ignorefile .trivyignore --exit-code 1
}

step_trivy_config() {
    need trivy || return $?
    trivy config . --severity CRITICAL,HIGH --ignorefile .trivyignore --exit-code 1
}

step_gitleaks() {
    # Scans the full git history with the project's .gitleaks.toml. Values are redacted.
    if command -v gitleaks > /dev/null 2>&1; then
        gitleaks detect --source . --config .gitleaks.toml --redact --log-opts="--all"
    else
        need docker || return $?
        docker run --rm -v "$PWD:/repo" ghcr.io/gitleaks/gitleaks:latest detect --source /repo \
            --config /repo/.gitleaks.toml --redact --log-opts="--all"
    fi
}

step_compose_config() {
    need docker || return $?
    docker compose config --quiet
}

step_nft_syntax() {
    # Syntax-checks the host firewall rules inside an unprivileged network namespace.
    need nft || return $?
    if command -v unshare > /dev/null 2>&1; then
        unshare -rn nft -c -f docker/nftables/kura.nft
    else
        nft -c -f docker/nftables/kura.nft
    fi
}

# ---------- stack group: needs the Docker stack to be up ----------

step_zap_baseline() {
    # Authenticated passive ZAP scan. Needs the stack, seeded demo data and ZAP_PASSWORD.
    need docker || return $?
    [ -n "${ZAP_PASSWORD:-}" ] || { echo "SKIP: set ZAP_PASSWORD to the demo account password"; return 77; }
    scripts/zap-baseline.sh
}

step_trivy_images() {
    need trivy || return $?
    local rc=0
    for image in kura-web:latest kura-nginx:latest; do
        trivy image "$image" --severity CRITICAL,HIGH --ignore-unfixed --ignorefile .trivyignore --exit-code 1 || rc=1
    done
    return "$rc"
}

step_restore_drill() {
    # Restores the latest backup into a throwaway volume with no network and compares row counts.
    need docker || return $?
    ./setup.sh restore-drill
}

step_egress_firewall() {
    # Checks that the firewall allowlist works: the allowed relay is reachable and a random host is not.
    need docker || return $?
    if [ "$(id -u)" != 0 ]; then echo "SKIP: needs root to read the nftables ruleset (run with sudo)"; return 77; fi
    nft list table inet kura_host || return 1
    docker network inspect kura_egress --format 'bridge={{index .Options "com.docker.network.bridge.name"}}' || return 1
    docker compose exec -T web python -c "import socket; socket.create_connection(('smtp.gmail.com',587),5); print('allowed host reachable')" \
        || { echo "allowed host NOT reachable"; return 1; }
    if docker compose exec -T web python -c "import socket; socket.create_connection(('example.com',443),5)" > /dev/null 2>&1; then
        echo "blocked host was reachable: the allowlist is not working"
        return 1
    fi
    echo "blocked host unreachable, as intended"
}

# ---------- active group: noisy scanners, localhost only ----------

step_nmap() {
    need nmap || return $?; local_only_target || return 1
    nmap -sT -sV -p- "$ACTIVE_TARGET"
}

step_nikto() {
    need nikto || return $?; local_only_target || return 1
    nikto -h "https://$ACTIVE_TARGET:443"
}

step_ffuf() {
    need ffuf || return $?; local_only_target || return 1
    [ -n "${FFUF_WORDLIST:-}" ] || { echo "SKIP: set FFUF_WORDLIST"; return 77; }
    ffuf -u "https://$ACTIVE_TARGET/FUZZ" -w "$FFUF_WORDLIST" -k -mc all -fc 404
}

step_sqlmap() {
    need sqlmap || return $?; local_only_target || return 1
    sqlmap -u "https://$ACTIVE_TARGET/login/" --forms --batch --level 3 --risk 2
    if [ -n "${SQLMAP_COOKIE:-}" ]; then
        # The cookie is passed to sqlmap but never echoed or written to the log.
        sqlmap -u "https://$ACTIVE_TARGET/courses/" --cookie="$SQLMAP_COOKIE" --batch --level 3 --risk 2 2>&1 \
            | sed -E 's/(__Host-kura_session=)[A-Za-z0-9]+/\1<redacted>/g'
    fi
}

step_hydra() {
    need hydra || return $?; local_only_target || return 1
    [ -n "${HYDRA_USER:-}" ] && [ -n "${HYDRA_WORDLIST:-}" ] || { echo "SKIP: set HYDRA_USER and HYDRA_WORDLIST"; return 77; }
    hydra -l "$HYDRA_USER" -P "$HYDRA_WORDLIST" "$ACTIVE_TARGET" \
        https-post-form "/login/:email=^USER^&password=^PASS^:F=Invalid"
}

run_step ruff default step_ruff
run_step deploy-check default step_deploy_check
run_step django-suite default step_django_suite
run_step semgrep default step_semgrep
run_step pip-audit default step_pip_audit
run_step trivy-fs default step_trivy_fs
run_step trivy-config default step_trivy_config
run_step gitleaks default step_gitleaks
run_step compose-config default step_compose_config
run_step nft-syntax default step_nft_syntax
run_step zap-baseline stack step_zap_baseline
run_step trivy-images stack step_trivy_images
run_step restore-drill stack step_restore_drill
run_step egress-firewall stack step_egress_firewall
run_step nmap active step_nmap
run_step nikto active step_nikto
run_step ffuf active step_ffuf
run_step sqlmap active step_sqlmap
run_step hydra active step_hydra

[ "$LIST" = 1 ] && exit 0

echo
echo "Security test summary ($DATE, commit $(git rev-parse --short HEAD 2>/dev/null || echo unknown))"
printf '%-18s %-8s %-6s %5s  %s\n' STEP GROUP RESULT TIME LOG
for line in "${RESULTS[@]}"; do echo "$line"; done
echo
if [ "$FAILED" -gt 0 ]; then
    echo "$FAILED step(s) failed. Logs are in $OUT/"
    exit 1
fi
echo "No step failed. Logs are in $OUT/"
