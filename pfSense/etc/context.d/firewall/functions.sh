#!/bin/sh
# Helper functions for context firewall module

: "${FIREWALL_LOG_FILE:=/var/log/context-firewall.log}"

ensure_log_dir() {
    local log_dir
    log_dir=$(dirname -- "$FIREWALL_LOG_FILE")
    [ -d "$log_dir" ] || mkdir -p "$log_dir"
}

log() {
    [ "${FIREWALL_LOG:-on}" = "on" ] || return 0
    ensure_log_dir
    local ts
    ts=$(date +"%Y-%m-%d %H:%M:%S")
    printf '%s [context-firewall] %s\n' "$ts" "$*" >>"$FIREWALL_LOG_FILE"
}

require_command() {
    local cmd
    cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        log "Missing required command: $cmd"
        return 1
    fi
    return 0
}

normalize_space() {
    printf '%s' "$*" | tr '\n\t' '  ' | tr -s ' '
}

sanitize_list() {
    # Turn comma/semicolon separated input into space separated tokens
    normalize_space "${1:-}" | tr ',;' ' ' | tr -s ' '
}

run_php_inline() {
    local script_file rc
    script_file=$(mktemp /tmp/context-firewall-php.XXXXXX)
    cat >"$script_file"
    /usr/local/bin/php -q "$script_file"
    rc=$?
    rm -f "$script_file"
    return $rc
}
