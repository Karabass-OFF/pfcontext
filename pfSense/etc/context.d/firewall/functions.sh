#!/bin/sh
#
# functions.sh - Common helper routines for the ContextFW firewall module.
#
# This file is sourced by the firewall.sh entry point as well as all
# sub-modules.  It provides logging helpers, dependency checks, state file
# handling and convenience wrappers for executing shell commands in a pfSense
# environment.  All functions are written in POSIX sh and avoid using external
# utilities unless absolutely required.
#

# Global paths used across modules
: "${CONTEXT_FW_LOG:=/var/log/context-firewall.log}"
: "${CONTEXT_FW_STATE:=/var/run/context-firewall.state}"
: "${CONTEXT_FW_LOCK:=/var/run/context-firewall.lock}"
: "${CONTEXT_FW_WORKDIR:=/var/run}"
: "${CONTEXT_FW_DEBUG:=off}"

# shellcheck shell=sh disable=SC2039
umask 077
mkdir -p "$(dirname "$CONTEXT_FW_LOG")" >/dev/null 2>&1 || true
mkdir -p "$CONTEXT_FW_WORKDIR" >/dev/null 2>&1 || true

log_ts()
{
    date '+%Y-%m-%d %H:%M:%S'
}

log()
{
    level=$1
    shift
    prefix="[$level]"
    if [ "$CONTEXT_FW_DEBUG" = "on" ]; then
        prefix="[DEBUG]$prefix"
    fi
    printf '%s %s %s\n' "$(log_ts)" "$prefix" "$*" >>"$CONTEXT_FW_LOG"
}

log_info()
{
    log INFO "$*"
}

log_warn()
{
    log WARN "$*"
}

log_error()
{
    log ERROR "$*"
}

log_debug()
{
    [ "$CONTEXT_FW_DEBUG" = "on" ] || return 0
    log DEBUG "$*"
}

fatal()
{
    log_error "$*"
    cleanup_lock
    exit 1
}

require_cmd()
{
    cmd=$1
    if ! command -v "$cmd" >/dev/null 2>&1; then
        fatal "Required command '$cmd' not found"
    fi
}

acquire_lock()
{
    if [ -f "$CONTEXT_FW_LOCK" ]; then
        now=$(date +%s)
        lock_ts=$(stat -f %m "$CONTEXT_FW_LOCK" 2>/dev/null || stat -c %Y "$CONTEXT_FW_LOCK" 2>/dev/null || echo 0)
        age=$((now - lock_ts))
        if [ "$age" -lt 600 ]; then
            log_warn "[locked] Another context-firewall instance is running"
            exit 0
        fi
        log_warn "Stale lock detected (age ${age}s) — overriding"
    fi
    echo "$$" >"$CONTEXT_FW_LOCK" || fatal "Unable to acquire lock $CONTEXT_FW_LOCK"
    trap cleanup_lock EXIT HUP INT TERM
    log_debug "Lock acquired"
}

cleanup_lock()
{
    [ -f "$CONTEXT_FW_LOCK" ] && rm -f "$CONTEXT_FW_LOCK"
}

read_state()
{
    if [ -f "$CONTEXT_FW_STATE" ]; then
        # shellcheck disable=SC1090
        . "$CONTEXT_FW_STATE"
    else
        CONTEXT_FW_STATE_HASH=""
        CONTEXT_FW_STATE_PENDING=""
    fi
}

write_state()
{
    tmp="$CONTEXT_FW_STATE.$$"
    {
        echo "CONTEXT_FW_STATE_HASH='${CONTEXT_FW_STATE_HASH:-}'"
        echo "CONTEXT_FW_STATE_PENDING='${CONTEXT_FW_STATE_PENDING:-}'"
    } >"$tmp"
    mv "$tmp" "$CONTEXT_FW_STATE"
}

set_state()
{
    CONTEXT_FW_STATE_HASH=$1
    CONTEXT_FW_STATE_PENDING=${2:-}
    write_state
}

compute_hash()
{
    data=$1
    printf '%s' "$data" | cksum | awk '{print $1}'
}

ensure_work_copy()
{
    src=$1
    dst=$2
    if [ ! -f "$src" ]; then
        fatal "Source config $src not found"
    fi
    cp "$src" "$dst" || fatal "Unable to copy $src to $dst"
    log_debug "Working copy created at $dst"
}

run_cmd()
{
    log_debug "Executing: $*"
    if [ "$CONTEXT_FW_DEBUG" = "on" ]; then
        "$@" 2>>"$CONTEXT_FW_LOG"
    else
        "$@" >>"$CONTEXT_FW_LOG" 2>&1
    fi
    status=$?
    if [ $status -ne 0 ]; then
        log_error "Command failed ($status): $*"
        return $status
    fi
    return 0
}

validate_ruleset()
{
    work_xml=$1
    tmp_rules="/tmp/context-fw.rules"
    if command -v php >/dev/null 2>&1 && [ -f /etc/rc.filter_configure_sync ]; then
        if ! run_cmd php -f /etc/rc.filter_configure_sync "$work_xml" "$tmp_rules"; then
            log_error "Failed to generate rules from $work_xml"
            return 1
        fi
    else
        log_warn "php or /etc/rc.filter_configure_sync unavailable — skipping rules generation"
        return 0
    fi
    if command -v pfctl >/dev/null 2>&1; then
        if ! run_cmd pfctl -nf "$tmp_rules"; then
            log_error "pfctl syntax check failed"
            return 1
        fi
    else
        log_warn "pfctl not available — skipping syntax check"
    fi
    return 0
}

apply_rules()
{
    if [ "${FIREWALL_RELOAD:-auto}" = "manual" ]; then
        log_warn "[pending] Reload skipped (manual mode)"
        CONTEXT_FW_STATE_PENDING=pending
        write_state
        return 0
    fi

    if ! command -v /usr/local/sbin/pfSsh.php >/dev/null 2>&1; then
        log_warn "pfSsh.php not available — cannot reload filter"
        return 1
    fi
    if ! run_cmd /usr/local/sbin/pfSsh.php playback reloadfilter; then
        log_error "reloadfilter failed"
        return 1
    fi
    if [ "${CONTEXT_FW_RELOAD_ALL:-no}" = "yes" ] && command -v /etc/rc.reload_all >/dev/null 2>&1; then
        run_cmd /etc/rc.reload_all || return 1
    fi
    log_info "Rules reloaded"
    CONTEXT_FW_STATE_PENDING=""
    write_state
    return 0
}

backup_current_config()
{
    config_file=$1
    dest_dir=/cf/conf/backup
    mkdir -p "$dest_dir" >/dev/null 2>&1 || true
    stamp=$(date +%Y.%m.%d.%H.%M.%S)
    dest="$dest_dir/config.xml.$stamp"
    cp "$config_file" "$dest" && log_info "Backup stored at $dest"
}

install_config()
{
    work_xml=$1
    target=${2:-/cf/conf/config.xml}
    tmp="$target.contextfw.$$"
    cp "$work_xml" "$tmp" || return 1
    mv "$tmp" "$target" || return 1
    log_info "Config updated at $target"
    return 0
}

rollback_config()
{
    backup_dir=/cf/conf/backup
    last_backup=$(ls -t "$backup_dir"/config.xml.* 2>/dev/null | head -n1)
    if [ -n "$last_backup" ]; then
        cp "$last_backup" /cf/conf/config.xml && log_warn "[rollback] Restored $last_backup"
    else
        log_error "No backup available for rollback"
    fi
}
