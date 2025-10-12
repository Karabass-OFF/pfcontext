#!/bin/sh
#
# mod_forward.sh - Inter-LAN forwarding rules for the ContextFW firewall module.
#
# Handles allow/deny policies between LAN interfaces based on context
# parameters.  Ensures fail-safe checks and maintains rules with the ContextFW
# prefix only.
#

. "$(dirname "$0")/functions.sh"
. "$(dirname "$0")/vars.sh"

list_lan_interfaces()
{
    work_xml=$1
    xml sel -t -m "//interfaces/*" -v "concat(name(),'|',if,'|',descr)" -n "$work_xml" 2>/dev/null |
        while IFS='|' read -r ifname ifdev ifdescr; do
            ifdescr_lc=$(printf '%s' "$ifdescr" | tr '[:upper:]' '[:lower:]')
            if [ "${ifdescr_lc#*wan}" != "$ifdescr_lc" ]; then
                continue
            fi
            if [ -n "$FIREWALL_NAT_OUT_IF" ] && [ "$ifdev" = "$FIREWALL_NAT_OUT_IF" ]; then
                continue
            fi
            printf '%s\n' "$ifname"
        done
}

fail_safe_check()
{
    work_xml=$1
    lan_list=$2
    for lan in $lan_list; do
        suspicious=$(xml sel -t -m "//filter/rule[type='pass' and interface='$lan' and not(starts-with(descr,'$CONTEXT_FW_PREFIX'))]" -v "descr" -n "$work_xml" 2>/dev/null)
        if [ -n "$suspicious" ]; then
            log_warn "Fail-safe: found non-context pass rule on $lan: $suspicious"
        fi
    done
}

clear_context_forward_rules()
{
    work_xml=$1
    xml ed -L -d "//filter/rule[starts-with(descr,'$CONTEXT_FW_PREFIX') and not(starts-with(descr,'$CONTEXT_FW_PREFIX DNAT allow'))]" "$work_xml" 2>/dev/null || true
}

append_filter_rule()
{
    work_xml=$1
    type=$2
    interface=$3
    proto=$4
    src_type=$5
    src_value=$6
    dst_type=$7
    dst_value=$8
    descr=$9

    xml ed -L \
        -s "//filter" -t elem -n "ruleTMP" -v "" \
        -s "//filter/ruleTMP" -t elem -n "type" -v "$type" \
        -s "//filter/ruleTMP" -t elem -n "interface" -v "$interface" \
        -s "//filter/ruleTMP" -t elem -n "protocol" -v "$proto" \
        -s "//filter/ruleTMP" -t elem -n "descr" -v "$descr" \
        -s "//filter/ruleTMP" -t elem -n "source" -v "" \
        "$work_xml" >/dev/null

    case $src_type in
        any) xml ed -L -s "//filter/ruleTMP/source" -t elem -n "any" -v "" "$work_xml" >/dev/null ;;
        network) xml ed -L -s "//filter/ruleTMP/source" -t elem -n "network" -v "$src_value" "$work_xml" >/dev/null ;;
        address) xml ed -L -s "//filter/ruleTMP/source" -t elem -n "address" -v "$src_value" "$work_xml" >/dev/null ;;
        alias) xml ed -L -s "//filter/ruleTMP/source" -t elem -n "address" -v "$src_value" "$work_xml" >/dev/null ;;
    esac

    xml ed -L -s "//filter/ruleTMP" -t elem -n "destination" -v "" "$work_xml" >/dev/null
    case $dst_type in
        any) xml ed -L -s "//filter/ruleTMP/destination" -t elem -n "any" -v "" "$work_xml" >/dev/null ;;
        network) xml ed -L -s "//filter/ruleTMP/destination" -t elem -n "network" -v "$dst_value" "$work_xml" >/dev/null ;;
        address) xml ed -L -s "//filter/ruleTMP/destination" -t elem -n "address" -v "$dst_value" "$work_xml" >/dev/null ;;
        alias) xml ed -L -s "//filter/ruleTMP/destination" -t elem -n "address" -v "$dst_value" "$work_xml" >/dev/null ;;
    esac

    xml ed -L -r "//filter/ruleTMP" -v "rule" "$work_xml" >/dev/null
}

apply_forward_module()
{
    work_xml=$1
    lan_list=$(list_lan_interfaces "$work_xml")
    [ -n "$lan_list" ] || {
        log_warn "No LAN interfaces detected"
        return 0
    }

    fail_safe_check "$work_xml" "$lan_list"

    clear_context_forward_rules "$work_xml"

    case "$FIREWALL_DEFAULT_FORWARD" in
        allow)
            for lan in $lan_list; do
                descr="$CONTEXT_FW_PREFIX default allow $lan"
                append_filter_rule "$work_xml" "pass" "$lan" "any" "any" "" "any" "" "$descr"
            done
            ;;
        *)
            for lan in $lan_list; do
                descr="$CONTEXT_FW_PREFIX default deny $lan"
                append_filter_rule "$work_xml" "block" "$lan" "any" "any" "" "any" "" "$descr"
            done
            ;;
    esac

    # Allow interface groups if configured
    if [ -n "$FW_FORWARD_IF_LIST" ]; then
        set -- $FW_FORWARD_IF_LIST
        while [ "$#" -gt 1 ]; do
            cur=$1
            shift
            for target in "$@"; do
                descr="$CONTEXT_FW_PREFIX allow $cur-$target"
                append_filter_rule "$work_xml" "pass" "$cur" "any" "network" "$cur" "network" "$target" "$descr"
                descr="$CONTEXT_FW_PREFIX allow $target-$cur"
                append_filter_rule "$work_xml" "pass" "$target" "any" "network" "$target" "network" "$cur" "$descr"
            done
        done
    fi

    if [ -n "$FW_FORWARD_IP_LIST" ]; then
        for ip in $FW_FORWARD_IP_LIST; do
            for lan in $lan_list; do
                descr="$CONTEXT_FW_PREFIX allow host $ip on $lan"
                append_filter_rule "$work_xml" "pass" "$lan" "any" "any" "" "address" "$ip" "$descr"
            done
        done
    fi

    if [ -n "$FW_BLOCK_NETS_LIST" ]; then
        for lan in $lan_list; do
            descr="$CONTEXT_FW_PREFIX block nets on $lan"
            append_filter_rule "$work_xml" "block" "$lan" "any" "any" "" "alias" "ContextFW_BLOCK_NETS" "$descr"
        done
    fi
}
