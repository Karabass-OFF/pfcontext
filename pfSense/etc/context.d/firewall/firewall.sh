#!/bin/sh
#
# firewall.sh - Entry point for the ContextFW firewall module for pfSense.
#
# This script orchestrates NAT, DNAT and forwarding rule generation based on
# context variables provided by OpenNebula.  The module operates on a temporary
# copy of config.xml, validates the resulting ruleset and applies the
# configuration using pfSense automation utilities.
#

PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
SCRIPT_DIR=$(dirname "$0")
CONTEXT_FW_LOG=${CONTEXT_FW_LOG:-/var/log/context-firewall.log}
CONTEXT_FW_STATE=${CONTEXT_FW_STATE:-/var/run/context-firewall.state}
CONTEXT_FW_LOCK=${CONTEXT_FW_LOCK:-/var/run/context-firewall.lock}
CONTEXT_FW_WORKDIR=${CONTEXT_FW_WORKDIR:-/var/run}

. "$SCRIPT_DIR/functions.sh"
. "$SCRIPT_DIR/vars.sh"

main()
{
    load_context_firewall_vars

    if [ "$FIREWALL_LOG" = "off" ]; then
        CONTEXT_FW_LOG=/dev/null
    fi

    if [ "$CONTEXT_FW_DEBUG" = "on" ]; then
        set -x
    fi

    log_info "ContextFW module start"

    if [ "$FIREWALL_ENABLE" = "off" ]; then
        log_warn "FIREWALL_ENABLE=off — skipping"
        exit 0
    fi
    if [ "$FIREWALL_PFCTL" = "off" ]; then
        log_warn "FIREWALL_PFCTL=off — skipping"
        exit 0
    fi

    acquire_lock
    read_state

    if [ "$FIREWALL_RELOAD" = "manual" ] && [ "${CONTEXT_FW_STATE_PENDING:-}" = "pending" ]; then
        log_warn "[pending] Previous manual changes not applied"
        exit 0
    fi

    require_cmd xml

    backup_xml=${backup_xml_file:-/cf/conf/config.xml}
    if [ ! -f "$backup_xml" ]; then
        log_warn "backup_xml_file not provided, using live config"
        backup_xml=/cf/conf/config.xml
    fi

    work_xml="$CONTEXT_FW_WORKDIR/context-firewall.$$".xml
    ensure_work_copy "$backup_xml" "$work_xml"

    state_payload=$(printf '%s\n' \
        "$FIREWALL_NAT_OUT_IF" \
        "$FIREWALL_FORWARD_ALLOW_IF" \
        "$FIREWALL_FORWARD_ALLOW_IP" \
        "$FIREWALL_NAT_NETS" \
        "$FIREWALL_NAT_HOSTS" \
        "$FIREWALL_NAT_ALLOW_NETS" \
        "$FIREWALL_BLOCK_NETS" \
        "$FIREWALL_PORT_FORWARD_LIST" \
        "$FIREWALL_DEFAULT_FORWARD" \
        "$FIREWALL_RELOAD")
    new_hash=$(compute_hash "$state_payload")

    if [ "${CONTEXT_FW_STATE_HASH:-}" = "$new_hash" ] && [ "${CONTEXT_FW_STATE_PENDING:-}" != "pending" ]; then
        log_info "No changes detected"
        rm -f "$work_xml"
        exit 0
    fi

    apply_nat_module "$work_xml"
    apply_dnat_module "$work_xml"
    apply_forward_module "$work_xml"

    if ! validate_ruleset "$work_xml"; then
        log_error "Validation failed"
        rollback_config
        rm -f "$work_xml"
        exit 1
    fi

    cp "$work_xml" "$backup_xml" || fatal "Failed to update backup copy"
    backup_current_config /cf/conf/config.xml
    if ! install_config "$work_xml" /cf/conf/config.xml; then
        log_error "Failed to install config"
        rm -f "$work_xml"
        exit 1
    fi

    if ! apply_rules; then
        log_error "Failed to reload rules"
        rollback_config
        rm -f "$work_xml"
        exit 1
    fi

    rm -f "$work_xml"
    current_pending=${CONTEXT_FW_STATE_PENDING:-}
    set_state "$new_hash" "$current_pending"
    log_info "ContextFW module completed"
}

main "$@"
