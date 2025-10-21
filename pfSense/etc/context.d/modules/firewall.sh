#!/bin/sh

# Firewall-related helpers for ContextOnly.

MGMT_SHOULD_APPLY="off"

_firewall_log() {
    log_file="$1"
    message="$2"
    if [ -n "$log_file" ]; then
        printf '%s [context-firewall] %s\n' "$(date)" "$message" >> "$log_file"
    fi
}

_firewall_find_php() {
    if [ -x /usr/local/bin/php ]; then
        printf '%s' "/usr/local/bin/php"
    elif command -v php >/dev/null 2>&1; then
        command -v php
    else
        printf '%s' ""
    fi
}

_firewall_normalize_bool() {
    value="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
    case "$value" in
        1|true|yes|on|enabled)
            printf '%s' "on"
            ;;
        *)
            printf '%s' ""
            ;;
    esac
}

_prepare_mgmt_sources() {
    for candidate in MGMT_ALLOWED_SOURCES MGMT_ALLOWED_IPS MGMT_SOURCE_ADDRESSES MGMT_SOURCE_IPS MGMT_SOURCE; do
        eval "val=\${$candidate:-}"
        if [ -n "$val" ]; then
            printf '%s' "$val"
            return 0
        fi
    done
    return 1
}

prepare_mgmt_firewall_rules() {
    backup_file="$1"
    log_file="$2"
    php_bin="$(_firewall_find_php)"
    script="$SCRIPT_DIR/modules/firewall_mgmt.php"

    mgmt_enabled=$(_firewall_normalize_bool "${MGMT_ENABLE:-${MGMT_ENABLED:-}}")
    mgmt_targets=$(printf '%s' "${MGMT_TARGETS:-}" | tr '\n' ' ' | sed -E -e 's/[[:space:]]+/ /g' -e 's/^ //' -e 's/ $//')
    mgmt_sources=$(_prepare_mgmt_sources || printf '%s' "")
    mgmt_ports="${MGMT_TCP_PORTS:-${MGMT_PORTS:-}}"

    if [ ! -f "$script" ]; then
        _firewall_log "$log_file" "firewall_mgmt.php not found, skipping management firewall provisioning"
        return 0
    fi

    if [ -z "$php_bin" ]; then
        _firewall_log "$log_file" "php binary not found, unable to manage firewall rules"
        return 1
    fi

    output=$("$php_bin" "$script" prepare "$backup_file" "$log_file" "${mgmt_enabled:-off}" "${mgmt_targets:-}" "${mgmt_sources:-}" "${mgmt_ports:-}" 2>>"$log_file")
    status=$?
    if [ $status -ne 0 ]; then
        _firewall_log "$log_file" "management firewall provisioning command failed (exit $status)"
        MGMT_SHOULD_APPLY="off"
        return $status
    fi

    if printf '%s' "$output" | grep -q 'CHANGED=1'; then
        MGMT_SHOULD_APPLY="on"
        _firewall_log "$log_file" "management firewall rules updated"
    else
        MGMT_SHOULD_APPLY="off"
        _firewall_log "$log_file" "management firewall rules unchanged"
    fi
}

apply_mgmt_firewall_runtime() {
    log_file="$1"
    php_bin="$(_firewall_find_php)"
    script="$SCRIPT_DIR/modules/firewall_mgmt.php"

    if [ "${MGMT_SHOULD_APPLY:-off}" != "on" ]; then
        _firewall_log "$log_file" "skip firewall apply (no changes detected)"
        return 0
    fi

    if [ ! -f "$script" ]; then
        _firewall_log "$log_file" "firewall_mgmt.php not found, cannot apply firewall rules"
        return 0
    fi

    if [ -z "$php_bin" ]; then
        _firewall_log "$log_file" "php binary not found, cannot apply firewall rules"
        return 1
    fi

    if "$php_bin" "$script" apply "$log_file" >>"$log_file" 2>&1; then
        _firewall_log "$log_file" "management firewall rules applied"
    else
        _firewall_log "$log_file" "failed to apply management firewall rules"
        return 1
    fi
}
