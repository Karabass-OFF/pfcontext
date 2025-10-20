#!/bin/sh
#
# Firewall helper functions for configuring management-only interfaces.

: "${FIREWALL_LOG:=/var/log/context-firewall.log}"
FIREWALL_TAG="[context-firewall]"

firewall_log() {
    local level message
    level="$1"
    shift
    message="$*"
    mkdir -p "$(dirname "$FIREWALL_LOG")"
    printf '%s %s [%s] %s\n' "$(date)" "$FIREWALL_TAG" "$level" "$message" >>"$FIREWALL_LOG"
}

ensure_filter_section() {
    local xml_file="$1"
    local filter_count
    filter_count=$(xml sel -t -v "count(//filter)" "$xml_file" 2>/dev/null || echo 0)
    if [ "${filter_count:-0}" -eq 0 ]; then
        if xml ed -L -s "//pfsense" -t elem -n "filter" -v "" "$xml_file"; then
            firewall_log INFO "Created missing <filter> section"
        else
            firewall_log ERROR "Failed to create <filter> section in $xml_file"
            return 1
        fi
    fi
    return 0
}

remove_management_rules() {
    local xml_file="$1"
    local interface="$2"
    local removed
    removed=$(xml sel -t -v "count(//filter/rule[interface='${interface}' and starts-with(descr,'[CTX-MGMT]')])" "$xml_file" 2>/dev/null || echo 0)
    if [ "${removed:-0}" -gt 0 ]; then
        if xml ed -L -d "//filter/rule[interface='${interface}' and starts-with(descr,'[CTX-MGMT]')]" "$xml_file"; then
            firewall_log INFO "Removed ${removed} existing [CTX-MGMT] rules from interface ${interface}"
        else
            firewall_log ERROR "Failed to remove previous [CTX-MGMT] rules from interface ${interface}"
            return 1
        fi
    fi
    return 0
}

remove_default_allow_rules() {
    local xml_file="$1"
    local interface="$2"
    local iface_upper descr
    iface_upper=$(printf '%s' "$interface" | tr '[:lower:]' '[:upper:]')
    for descr in "Default allow ${iface_upper} to any rule" "Default allow ${iface_upper} IPv6 to any rule"; do
        if [ "$(xml sel -t -v "count(//filter/rule[interface='${interface}' and descr='${descr}'])" "$xml_file" 2>/dev/null || echo 0)" -gt 0 ]; then
            if xml ed -L -d "//filter/rule[interface='${interface}' and descr='${descr}']" "$xml_file"; then
                firewall_log INFO "Removed default allow rule '${descr}'"
            else
                firewall_log ERROR "Failed to remove default allow rule '${descr}'"
                return 1
            fi
        fi
    done
    return 0
}

append_management_allow_rule() {
    local xml_file="$1"
    local interface="$2"
    local ipprotocol="$3"
    local protocol="$4"
    local source_network="$5"
    local destination_node="$6"
    local destination_value="$7"
    local port="$8"
    local descr="$9"

    if ! xml ed -L \
        -s "//filter" -t elem -n "rule" -v "" \
        -s "//filter/rule[last()]" -t elem -n "type" -v "pass" \
        -s "//filter/rule[last()]" -t elem -n "interface" -v "$interface" \
        -s "//filter/rule[last()]" -t elem -n "ipprotocol" -v "$ipprotocol" \
        -s "//filter/rule[last()]" -t elem -n "protocol" -v "$protocol" \
        -s "//filter/rule[last()]" -t elem -n "source" -v "" \
        -s "//filter/rule[last()]/source" -t elem -n "network" -v "$source_network" \
        -s "//filter/rule[last()]" -t elem -n "destination" -v "" \
        -s "//filter/rule[last()]/destination" -t elem -n "$destination_node" -v "$destination_value" \
        -s "//filter/rule[last()]/destination" -t elem -n "port" -v "$port" \
        -s "//filter/rule[last()]" -t elem -n "descr" -v "$descr" \
        "$xml_file"; then
        firewall_log ERROR "Failed to append management allow rule '${descr}'"
        return 1
    fi
    firewall_log INFO "Added rule '${descr}' (protocol ${protocol} ${ipprotocol} port ${port})"
    return 0
}

append_management_block_rule() {
    local xml_file="$1"
    local interface="$2"
    local ipprotocol="$3"
    local source_network="$4"
    local descr="$5"

    if ! xml ed -L \
        -s "//filter" -t elem -n "rule" -v "" \
        -s "//filter/rule[last()]" -t elem -n "type" -v "block" \
        -s "//filter/rule[last()]" -t elem -n "interface" -v "$interface" \
        -s "//filter/rule[last()]" -t elem -n "ipprotocol" -v "$ipprotocol" \
        -s "//filter/rule[last()]" -t elem -n "protocol" -v "any" \
        -s "//filter/rule[last()]" -t elem -n "source" -v "" \
        -s "//filter/rule[last()]/source" -t elem -n "network" -v "$source_network" \
        -s "//filter/rule[last()]" -t elem -n "destination" -v "" \
        -s "//filter/rule[last()]/destination" -t elem -n "any" -v "" \
        -s "//filter/rule[last()]" -t elem -n "descr" -v "$descr" \
        "$xml_file"; then
        firewall_log ERROR "Failed to append management block rule '${descr}'"
        return 1
    fi
    firewall_log INFO "Added rule '${descr}'"
    return 0
}

remove_static_routes_for_interface() {
    local xml_file="$1"
    local interface="$2"
    local removed
    removed=$(xml sel -t -v "count(//staticroutes/route[interface='${interface}'])" "$xml_file" 2>/dev/null || echo 0)
    if [ "${removed:-0}" -gt 0 ]; then
        if xml ed -L -d "//staticroutes/route[interface='${interface}']" "$xml_file"; then
            firewall_log INFO "Removed ${removed} static route(s) referencing ${interface}"
        else
            firewall_log ERROR "Failed to remove static routes for ${interface}"
            return 1
        fi
    fi
    return 0
}

strip_interface_gateway() {
    local xml_file="$1"
    local interface="$2"
    if [ "$(xml sel -t -v "count(//interfaces/${interface}/gateway)" "$xml_file" 2>/dev/null || echo 0)" -gt 0 ]; then
        if xml ed -L -d "//interfaces/${interface}/gateway" "$xml_file"; then
            firewall_log INFO "Removed gateway from ${interface} to exclude from routing"
        else
            firewall_log ERROR "Failed to remove gateway from ${interface}"
            return 1
        fi
    fi
    return 0
}

apply_management_interface_firewall() {
    local backup_xml_file="$1"
    local lockdown_flag="${MGMT_LOCKDOWN:-off}"
    local interface source_network ports port iface_upper dest_node dest_value iface_ip iface_ip6

    if [ ! -f "$backup_xml_file" ]; then
        firewall_log ERROR "Backup XML file $backup_xml_file not found"
        return 1
    fi

    if [ "${lockdown_flag}" != "on" ]; then
        firewall_log INFO "MGMT_LOCKDOWN is '${lockdown_flag}', skipping management firewall configuration"
        return 0
    fi

    interface="${MGMT_INTERFACE:-lan}"
    interface=$(printf '%s' "$interface" | tr '[:upper:]' '[:lower:]')

    if [ "$(xml sel -t -v "count(//interfaces/${interface})" "$backup_xml_file" 2>/dev/null || echo 0)" -eq 0 ]; then
        firewall_log WARN "Interface '${interface}' not present in config, nothing to lock down"
        return 0
    fi

    iface_upper=$(printf '%s' "$interface" | tr '[:lower:]' '[:upper:]')
    source_network="${MGMT_SOURCE_NETWORK:-$interface}"
    ports="${MGMT_ALLOWED_PORTS:-443 80 22}"

    ensure_filter_section "$backup_xml_file" || return 1
    remove_default_allow_rules "$backup_xml_file" "$interface" || return 1
    remove_management_rules "$backup_xml_file" "$interface" || return 1

    iface_ip=$(xml sel -t -v "//interfaces/${interface}/ipaddr" "$backup_xml_file" 2>/dev/null | head -n 1)
    iface_ip6=$(xml sel -t -v "//interfaces/${interface}/ipaddrv6" "$backup_xml_file" 2>/dev/null | head -n 1)

    if [ -z "$iface_ip" ] || [ "$iface_ip" = "dhcp" ] || [ "$iface_ip" = "" ]; then
        dest_node="address"
        dest_value="$interface"
    else
        dest_node="address"
        dest_value="$iface_ip"
    fi

    for port in $ports; do
        append_management_allow_rule "$backup_xml_file" "$interface" "inet" "tcp" "$source_network" "$dest_node" "$dest_value" "$port" "[CTX-MGMT] Allow ${iface_upper} management TCP port ${port}" || return 1
    done

    if [ -n "$iface_ip6" ] && [ "$iface_ip6" != "track6" ]; then
        dest_node="address"
        dest_value="$iface_ip6"
        for port in $ports; do
            append_management_allow_rule "$backup_xml_file" "$interface" "inet6" "tcp" "$source_network" "$dest_node" "$dest_value" "$port" "[CTX-MGMT] Allow ${iface_upper} management TCP port ${port} (IPv6)" || return 1
        done
    fi

    append_management_block_rule "$backup_xml_file" "$interface" "inet" "$source_network" "[CTX-MGMT] Block ${iface_upper} outbound IPv4" || return 1
    append_management_block_rule "$backup_xml_file" "$interface" "inet6" "$source_network" "[CTX-MGMT] Block ${iface_upper} outbound IPv6" || return 1

    remove_static_routes_for_interface "$backup_xml_file" "$interface" || return 1
    strip_interface_gateway "$backup_xml_file" "$interface" || return 1

    firewall_log INFO "Completed management lockdown for interface ${interface}"
    return 0
}