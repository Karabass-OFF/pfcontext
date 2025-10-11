#!/bin/sh
# Helper functions for context firewall module

PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin

LOG_FILE=${LOG_FILE:-/var/log/context-firewall.log}
STATE_FILE=${STATE_FILE:-/var/run/context-firewall.state}
RULE_FILE=${RULE_FILE:-/var/run/context-firewall.rules}
ANCHOR_NAME=${ANCHOR_NAME:-context/firewall}
TMPDIR_BASE=${TMPDIR_BASE:-/var/run}

init_logging() {
    case "${FIREWALL_LOG:-on}" in
        on|ON|On)
            :
            ;;
        *)
            LOG_FILE=/dev/null
            ;;
    esac
    if [ "$LOG_FILE" != "/dev/null" ]; then
        log_dir=$(dirname "$LOG_FILE")
        if [ ! -d "$log_dir" ]; then
            mkdir -p "$log_dir" 2>/dev/null || LOG_FILE=/dev/null
        fi
        if [ "$LOG_FILE" != "/dev/null" ] && [ ! -f "$LOG_FILE" ]; then
            : >"$LOG_FILE" 2>/dev/null || LOG_FILE=/dev/null
        fi
    fi
}

log_event() {
    action=$1
    shift
    message=$*
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    printf '%s [%s] %s\n' "$ts" "$action" "$message" >>"$LOG_FILE" 2>/dev/null
}

ensure_state_dir() {
    state_dir=$(dirname "$STATE_FILE")
    if [ ! -d "$state_dir" ]; then
        mkdir -p "$state_dir" 2>/dev/null || return 1
    fi
    return 0
}

normalize_spaces() {
    # shellcheck disable=SC2001
    echo "${1}" | sed -e 's/[\t\n]\+/ /g' -e 's/  */ /g' -e 's/^ *//' -e 's/ *$//'
}

list_contains() {
    needle=$1
    haystack=" $2 "
    case "$haystack" in
        *" $needle "*) return 0 ;;
        *) return 1 ;;
    esac
}

mk_workdir() {
    workdir=$(mktemp -d "$TMPDIR_BASE/context-fw.XXXXXX" 2>/dev/null)
    if [ -z "$workdir" ]; then
        workdir=$(mktemp -d /tmp/context-fw.XXXXXX 2>/dev/null)
    fi
    echo "$workdir"
}
