#!/usr/bin/env bash
# ============================================================================
# Self-Hosted Runner Health Check & Self-Heal
#
# Checks all GitHub Actions runners across all hosts and restarts any that
# are dead. Designed to run via cron every 5 minutes.
#
# Usage: bash scripts/runner-health-check.sh [--notify]
#   --notify: Create a GitHub issue if a runner was restarted
# ============================================================================
set -euo pipefail

NOTIFY=false
if [[ "${1:-}" == "--notify" ]]; then
    NOTIFY=true
fi

# ── Configuration ────────────────────────────────────────────────────────────

# Each entry: "host:service_name:display_name"
RUNNERS=(
    "localhost:actions.runner.rayketcham-lab.Ubuntu2:Ubuntu2 (ubuntu2)"
    "ubuntu3:actions.runner.rayketcham-lab.ubuntu3-runner:ubuntu3-runner (ubuntu3)"
    "rocky:actions.runner.rayketcham-lab.rocky-runner:rocky-runner (rocky)"
)

LOG_FILE="/tmp/runner-health-check.log"
RESTARTED=()
DEAD=()
HEALTHY=()

# ── Colors ───────────────────────────────────────────────────────────────────

if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BOLD=''
    RESET=''
fi

# ── Helper ───────────────────────────────────────────────────────────────────

log() {
    local ts
    ts=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    printf '%s %s\n' "${ts}" "$1" | tee -a "${LOG_FILE}"
}

# ── Check each runner ────────────────────────────────────────────────────────

printf '%s=== Runner Health Check ===%s\n' "${BOLD}" "${RESET}"
log "Starting runner health check"

for entry in "${RUNNERS[@]}"; do
    IFS=':' read -r host service display <<< "${entry}"

    printf '  %-35s ' "${display}:"

    # Check if the service is active
    if [[ "${host}" == "localhost" ]]; then
        status=$(systemctl is-active "${service}" 2>/dev/null || echo "unknown")
    else
        status=$(ssh -o ConnectTimeout=5 -o BatchMode=yes "${host}" \
            "systemctl is-active ${service}" 2>/dev/null || echo "unreachable")
    fi

    if [[ "${status}" == "active" ]]; then
        printf '%s[HEALTHY]%s\n' "${GREEN}" "${RESET}"
        HEALTHY+=("${display}")
    elif [[ "${status}" == "unreachable" ]]; then
        printf '%s[UNREACHABLE]%s — host not responding\n' "${RED}" "${RESET}"
        DEAD+=("${display} (host unreachable)")
        log "UNREACHABLE: ${display} — cannot SSH to ${host}"
    else
        printf '%s[DEAD]%s (status: %s) — attempting restart...\n' "${YELLOW}" "${RESET}" "${status}"
        log "DEAD: ${display} — status=${status}, attempting restart"

        # Attempt restart
        local restart_ok=false
        if [[ "${host}" == "localhost" ]]; then
            if sudo systemctl restart "${service}" 2>/dev/null; then
                restart_ok=true
            fi
        else
            if ssh -o ConnectTimeout=5 -o BatchMode=yes "${host}" \
                "sudo systemctl restart ${service}" 2>/dev/null; then
                restart_ok=true
            fi
        fi

        if [[ "${restart_ok}" == "true" ]]; then
            # Verify it came back
            sleep 3
            if [[ "${host}" == "localhost" ]]; then
                new_status=$(systemctl is-active "${service}" 2>/dev/null || echo "failed")
            else
                new_status=$(ssh -o ConnectTimeout=5 -o BatchMode=yes "${host}" \
                    "systemctl is-active ${service}" 2>/dev/null || echo "failed")
            fi

            if [[ "${new_status}" == "active" ]]; then
                printf '    %s→ Restarted successfully%s\n' "${GREEN}" "${RESET}"
                RESTARTED+=("${display}")
                log "RESTARTED: ${display} — now active"
            else
                printf '    %s→ Restart failed (status: %s)%s\n' "${RED}" "${new_status}" "${RESET}"
                DEAD+=("${display} (restart failed)")
                log "RESTART_FAILED: ${display} — status=${new_status}"
            fi
        else
            printf '    %s→ Restart command failed%s\n' "${RED}" "${RESET}"
            DEAD+=("${display} (restart command failed)")
            log "RESTART_FAILED: ${display} — command error"
        fi
    fi
done

# ── Summary ──────────────────────────────────────────────────────────────────

printf '\n%sSummary:%s\n' "${BOLD}" "${RESET}"
printf '  Healthy:    %d\n' "${#HEALTHY[@]}"
printf '  Restarted:  %d\n' "${#RESTARTED[@]}"
printf '  Dead:       %d\n' "${#DEAD[@]}"

# ── GitHub issue notification ────────────────────────────────────────────────

if [[ "${NOTIFY}" == "true" ]]; then
    if [[ ${#RESTARTED[@]} -gt 0 ]] || [[ ${#DEAD[@]} -gt 0 ]]; then
        if command -v gh > /dev/null 2>&1; then
            restarted_list=""
            for r in "${RESTARTED[@]}"; do
                restarted_list="${restarted_list}\n- ${r} (auto-restarted)"
            done
            dead_list=""
            for d in "${DEAD[@]}"; do
                dead_list="${dead_list}\n- ${d}"
            done

            title="ci: runner health alert on $(date -u '+%Y-%m-%d')"
            existing=$(gh issue list --repo rayketcham-lab/PKI-Client \
                --label runner-health --state open \
                --json number --jq '.[0].number // empty' 2>/dev/null || true)

            body="## Runner Health Alert

**Date:** $(date -u)

### Restarted
$(printf '%b' "${restarted_list:-None}")

### Still Dead
$(printf '%b' "${dead_list:-None}")

This issue was auto-created by the runner health check cron."

            if [[ -n "${existing}" ]]; then
                gh issue comment "${existing}" --repo rayketcham-lab/PKI-Client --body "${body}" 2>/dev/null || true
                log "NOTIFY: commented on issue #${existing}"
            else
                gh issue create --repo rayketcham-lab/PKI-Client \
                    --title "${title}" --label runner-health --body "${body}" 2>/dev/null || true
                log "NOTIFY: created new runner-health issue"
            fi
        fi
    fi
fi

# Exit non-zero if any runners are still dead (not just restarted)
if [[ ${#DEAD[@]} -gt 0 ]]; then
    exit 1
fi
