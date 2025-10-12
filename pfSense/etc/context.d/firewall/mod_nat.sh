#!/bin/sh
#
# mod_nat.sh - NAT (outbound) handler for the ContextFW firewall module.
#
# This module manages outbound NAT rules and supportive aliases based on the
# context variables exposed through vars.sh.  All operations target the working
# copy of config.xml supplied by firewall.sh.
#

. "$(dirname "$0")/functions.sh"
. "$(dirname "$0")/vars.sh"

add_or_replace_alias()
{
    work_xml=$1
    alias_name=$2
    alias_descr=$3
    alias_type=$4
    alias_content=$5

    [ -n "$alias_content" ] || {
        log_debug "Alias $alias_name empty — removing if exists"
        xml_edit -L -d "//aliases/alias[name='$alias_name']" "$work_xml" 2>/dev/null || true
        return 0
    }

    xml_edit -L -d "//aliases/alias[name='$alias_name']" "$work_xml" 2>/dev/null || true
    xml_edit -L \
        -s "//aliases" -t elem -n "aliasTMP" -v "" \
        -s "//aliases/aliasTMP" -t elem -n "name" -v "$alias_name" \
        -s "//aliases/aliasTMP" -t elem -n "type" -v "$alias_type" \
        -s "//aliases/aliasTMP" -t elem -n "address" -v "$alias_content" \
        -s "//aliases/aliasTMP" -t elem -n "descr" -v "$alias_descr" \
        -r "//aliases/aliasTMP" -v "alias" \
        "$work_xml" >/dev/null
}

clear_context_outbound_rules()
{
    work_xml=$1
    xml_edit -L -d "//nat/outbound/rule[starts-with(descr,'$CONTEXT_FW_PREFIX')]" "$work_xml" 2>/dev/null || true
}

append_outbound_rule()
{
    work_xml=$1
    source_tag=$2
    source_type=$3
    descr=$4

    xml_edit -L \
        -s "//nat/outbound" -t elem -n "ruleTMP" -v "" \
        -s "//nat/outbound/ruleTMP" -t elem -n "interface" -v "$FIREWALL_NAT_OUT_IF" \
        -s "//nat/outbound/ruleTMP" -t elem -n "protocol" -v "any" \
        -s "//nat/outbound/ruleTMP" -t elem -n "source" -v "" \
        -s "//nat/outbound/ruleTMP/source" -t elem -n "$source_type" -v "$source_tag" \
        -s "//nat/outbound/ruleTMP" -t elem -n "target" -v "" \
        -s "//nat/outbound/ruleTMP" -t elem -n "descr" -v "$descr" \
        -r "//nat/outbound/ruleTMP" -v "rule" \
        "$work_xml" >/dev/null
}

configure_outbound_nat()
{
    work_xml=$1

    if [ -z "$FIREWALL_NAT_OUT_IF" ]; then
        log_warn "FIREWALL_NAT_OUT_IF not defined — outbound NAT skipped"
        return 0
    fi

    xml_edit -L -u "//nat/outbound/mode" -v "advanced" "$work_xml" 2>/dev/null || {
        # Ensure mode node exists
        xml_edit -L -s "//nat/outbound" -t elem -n "mode" -v "advanced" "$work_xml" >/dev/null
    }

    clear_context_outbound_rules "$work_xml"

    for net in $FW_NAT_NETS_LIST; do
        descr="$CONTEXT_FW_PREFIX NAT $net"
        append_outbound_rule "$work_xml" "$net" network "$descr"
        log_info "Configured outbound NAT for network $net"
    done

    for host in $FW_NAT_HOSTS_LIST; do
        descr="$CONTEXT_FW_PREFIX NAT host $host"
        append_outbound_rule "$work_xml" "$host" address "$descr"
        log_info "Configured outbound NAT for host $host"
    done
}

configure_nat_aliases()
{
    work_xml=$1

    if [ -n "$FW_NAT_ALLOW_NETS_LIST" ]; then
        entries=$(printf '%s\n' $FW_NAT_ALLOW_NETS_LIST | paste -sd ',' -)
        add_or_replace_alias "$work_xml" \
            "ContextFW_NAT_ALLOW" \
            "$CONTEXT_FW_PREFIX NAT allow nets" \
            "network" \
            "$entries"
    else
        add_or_replace_alias "$work_xml" "ContextFW_NAT_ALLOW" "$CONTEXT_FW_PREFIX NAT allow nets" "network" ""
    fi

    if [ -n "$FW_BLOCK_NETS_LIST" ]; then
        entries=$(printf '%s\n' $FW_BLOCK_NETS_LIST | paste -sd ',' -)
        add_or_replace_alias "$work_xml" \
            "ContextFW_BLOCK_NETS" \
            "$CONTEXT_FW_PREFIX blocked nets" \
            "network" \
            "$entries"
    else
        add_or_replace_alias "$work_xml" "ContextFW_BLOCK_NETS" "$CONTEXT_FW_PREFIX blocked nets" "network" ""
    fi
}

apply_nat_module()
{
    work_xml=$1
    configure_nat_aliases "$work_xml"
    configure_outbound_nat "$work_xml"
}
