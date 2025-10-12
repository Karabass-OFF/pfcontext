#!/bin/sh
#
# mod_dnat.sh - Port forward (DNAT) handler for the ContextFW firewall module.
#
# Responsible for translating FIREWALL_PORT_FORWARD_LIST entries into NAT rules
# inside config.xml.  Optionally creates associated filter rules when requested.
#

. "$(dirname "$0")/functions.sh"
. "$(dirname "$0")/vars.sh"

clear_context_portforwards()
{
    work_xml=$1
    xml ed -L -d "//nat/rule[starts-with(descr,'$CONTEXT_FW_PREFIX')]" "$work_xml" 2>/dev/null || true
    xml ed -L -d "//filter/rule[starts-with(descr,'$CONTEXT_FW_PREFIX DNAT allow')]" "$work_xml" 2>/dev/null || true
}

append_destination()
{
    rule_path=$1
    address=$2
    port=$3
    work_xml=$4

    if [ -n "$address" ]; then
        xml ed -L -s "$rule_path" -t elem -n "address" -v "$address" "$work_xml" >/dev/null
    else
        xml ed -L -s "$rule_path" -t elem -n "any" -v "" "$work_xml" >/dev/null
    fi
    if [ -n "$port" ]; then
        xml ed -L -s "$rule_path" -t elem -n "port" -v "$port" "$work_xml" >/dev/null
    fi
}

append_portforward_rule()
{
    work_xml=$1
    if_name=$2
    proto=$3
    ext_addr=$4
    ext_port=$5
    int_ip=$6
    int_port=$7
    descr=$8
    assoc_rule=$9
    reflection=${10}
    disabled=${11}

    full_descr="$CONTEXT_FW_PREFIX DNAT ${descr}"
    xml ed -L \
        -s "//nat" -t elem -n "ruleTMP" -v "" \
        -s "//nat/ruleTMP" -t elem -n "interface" -v "$if_name" \
        -s "//nat/ruleTMP" -t elem -n "protocol" -v "$proto" \
        -s "//nat/ruleTMP" -t elem -n "source" -v "" \
        -s "//nat/ruleTMP/source" -t elem -n "any" -v "" \
        -s "//nat/ruleTMP" -t elem -n "destination" -v "" \
        "$work_xml" >/dev/null

    dest_path="//nat/ruleTMP/destination"

    case $ext_addr in
        wanaddress) dest_value="wanip" ;;
        vip:*) dest_value=${ext_addr#vip:} ;;
        '') dest_value="" ;;
        *) dest_value="$ext_addr" ;;
    esac

    append_destination "$dest_path" "$dest_value" "$ext_port" "$work_xml"

    xml ed -L \
        -s "//nat/ruleTMP" -t elem -n "target" -v "$int_ip" \
        -s "//nat/ruleTMP" -t elem -n "local-port" -v "$int_port" \
        -s "//nat/ruleTMP" -t elem -n "descr" -v "$full_descr" \
        "$work_xml" >/dev/null

    [ "$reflection" = "on" ] && xml ed -L -s "//nat/ruleTMP" -t elem -n "natreflection" -v "enable" "$work_xml" >/dev/null
    [ "$disabled" = "on" ] && xml ed -L -s "//nat/ruleTMP" -t elem -n "disabled" -v "" "$work_xml" >/dev/null

    if [ "$assoc_rule" = "on" ]; then
        xml ed -L \
            -s "//nat/ruleTMP" -t elem -n "associated-rule" -v "pass" \
            "$work_xml" >/dev/null
    else
        xml ed -L \
            -s "//nat/ruleTMP" -t elem -n "associated-rule" -v "disabled" \
            "$work_xml" >/dev/null
    fi

    xml ed -L -r "//nat/ruleTMP" -v "rule" "$work_xml" >/dev/null

    if [ "$assoc_rule" = "on" ]; then
        filter_descr="$CONTEXT_FW_PREFIX DNAT allow ${descr}"
        xml ed -L \
            -s "//filter" -t elem -n "ruleTMP" -v "" \
            -s "//filter/ruleTMP" -t elem -n "type" -v "pass" \
            -s "//filter/ruleTMP" -t elem -n "interface" -v "$if_name" \
            -s "//filter/ruleTMP" -t elem -n "protocol" -v "$proto" \
            -s "//filter/ruleTMP" -t elem -n "descr" -v "$filter_descr" \
            -s "//filter/ruleTMP" -t elem -n "source" -v "" \
            -s "//filter/ruleTMP/source" -t elem -n "any" -v "" \
            -s "//filter/ruleTMP" -t elem -n "destination" -v "" \
            "$work_xml" >/dev/null
        append_destination "//filter/ruleTMP/destination" "$int_ip" "$int_port" "$work_xml"
        [ "$disabled" = "on" ] && xml ed -L -s "//filter/ruleTMP" -t elem -n "disabled" -v "" "$work_xml" >/dev/null
        xml ed -L -r "//filter/ruleTMP" -v "rule" "$work_xml" >/dev/null
    fi
}

apply_dnat_module()
{
    work_xml=$1

    clear_context_portforwards "$work_xml"

    for entry in $FW_PORT_FORWARD_LIST; do
        [ -n "$entry" ] || continue
        if_name=""
        proto="tcp"
        ext_addr="wanaddress"
        ext_port=""
        int_ip=""
        int_port=""
        descr="Auto"
        assoc_rule="on"
        reflection="off"
        disabled="off"

        for kv in $(parse_pf_rule "$entry"); do
            key=${kv%%=*}
            val=${kv#*=}
            case $key in
                if) if_name=$val ;;
                proto) proto=$val ;;
                ext_addr) ext_addr=$val ;;
                ext_port) ext_port=$val ;;
                int_ip) int_ip=$val ;;
                int_port) int_port=$val ;;
                descr) descr=$val ;;
                assoc_rule) assoc_rule=$(normalise_bool "$val") ;;
                reflection) reflection=$(normalise_bool "$val") ;;
                disabled) disabled=$(normalise_bool "$val") ;;
            esac
        done

        [ -n "$if_name" ] || { log_warn "DNAT entry missing interface: $entry"; continue; }
        [ -n "$ext_port" ] || { log_warn "DNAT entry missing ext_port: $entry"; continue; }
        [ -n "$int_ip" ] || { log_warn "DNAT entry missing int_ip: $entry"; continue; }
        [ -n "$int_port" ] || { log_warn "DNAT entry missing int_port: $entry"; continue; }

        append_portforward_rule \
            "$work_xml" \
            "$if_name" \
            "$proto" \
            "$ext_addr" \
            "$ext_port" \
            "$int_ip" \
            "$int_port" \
            "$descr" \
            "$assoc_rule" \
            "$reflection" \
            "$disabled"
        log_info "DNAT rule applied for $descr"
    done
}
