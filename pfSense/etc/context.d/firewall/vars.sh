#!/bin/sh
#
# vars.sh - Context variable loader for the ContextFW firewall module.
#
# The pfSense ContextOnly script exposes variables defined inside context.sh.
# This helper normalises them, provides sane defaults and exposes utility
# routines used by other module scripts for iteration.
#

CONTEXT_FW_PREFIX="ContextFW:"

normalise_bool()
{
    val=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
    case $val in
        yes|on|true|1) echo on ;;
        no|off|false|0|'') echo off ;;
        *) echo "$val" ;;
    esac
}

split_commas()
{
    input=$1
    printf '%s' "$input" | tr ' ,' '\n' | awk 'NF'
}

split_spaces()
{
    input=$1
    printf '%s' "$input" | tr ' ' '\n' | awk 'NF'
}

split_semicolon()
{
    input=$1
    oldifs=$IFS
    IFS=';'
    for entry in $input; do
        trimmed=$(printf '%s' "$entry" | awk '{$1=$1;print}')
        [ -n "$trimmed" ] && printf '%s\n' "$trimmed"
    done
    IFS=$oldifs
}

load_context_firewall_vars()
{
    : "${FIREWALL_DEBUG:=off}"
    : "${FIREWALL_ENABLE:=on}"
    : "${FIREWALL_PFCTL:=on}"
    : "${FIREWALL_LOG:=on}"
    : "${FIREWALL_NAT_OUT_IF:=}"
    : "${FIREWALL_FORWARD_ALLOW_IF:=}"
    : "${FIREWALL_FORWARD_ALLOW_IP:=}"
    : "${FIREWALL_NAT_NETS:=}"
    : "${FIREWALL_NAT_HOSTS:=}"
    : "${FIREWALL_NAT_ALLOW_NETS:=}"
    : "${FIREWALL_BLOCK_NETS:=}"
    : "${FIREWALL_PORT_FORWARD_LIST:=}"
    : "${FIREWALL_DEFAULT_FORWARD:=deny}"
    : "${FIREWALL_RELOAD:=auto}"

    CONTEXT_FW_DEBUG=$(normalise_bool "$FIREWALL_DEBUG")
    FIREWALL_ENABLE=$(normalise_bool "$FIREWALL_ENABLE")
    FIREWALL_PFCTL=$(normalise_bool "$FIREWALL_PFCTL")
    FIREWALL_LOG=$(normalise_bool "$FIREWALL_LOG")
    FIREWALL_RELOAD_MODE=$(printf '%s' "$FIREWALL_RELOAD" | tr '[:upper:]' '[:lower:]')
    FIREWALL_RELOAD=$FIREWALL_RELOAD_MODE

    FW_FORWARD_IF_LIST=$(split_commas "$FIREWALL_FORWARD_ALLOW_IF")
    FW_FORWARD_IP_LIST=$(split_commas "$FIREWALL_FORWARD_ALLOW_IP")
    FW_NAT_NETS_LIST=$(split_spaces "$FIREWALL_NAT_NETS")
    FW_NAT_HOSTS_LIST=$(split_spaces "$FIREWALL_NAT_HOSTS")
    FW_NAT_ALLOW_NETS_LIST=$(split_spaces "$FIREWALL_NAT_ALLOW_NETS")
    FW_BLOCK_NETS_LIST=$(split_spaces "$FIREWALL_BLOCK_NETS")
    FW_PORT_FORWARD_LIST=$(split_semicolon "$FIREWALL_PORT_FORWARD_LIST")
}

parse_pf_rule()
{
    rule=$1
    oldifs=$IFS
    IFS=','
    for pair in $rule; do
        key=${pair%%=*}
        value=${pair#*=}
        key=$(printf '%s' "$key" | awk '{$1=$1;print}')
        value=$(printf '%s' "$value" | awk '{$1=$1;print}')
        [ -n "$key" ] && printf '%s=%s\n' "$key" "$value"
    done
    IFS=$oldifs
}
