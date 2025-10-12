#!/bin/sh
# Load and normalize context variables for firewall module

CONTEXT_FILE="/mnt/context/context.sh"

# Ensure context variables are loaded when running standalone
if [ -r "$CONTEXT_FILE" ]; then
    # shellcheck source=/dev/null
    . "$CONTEXT_FILE"
fi

: "${FIREWALL_ENABLE:=off}"
: "${FIREWALL_PFCTL:=on}"
: "${FIREWALL_NAT_OUT_IF:=wan}"
: "${FIREWALL_FORWARD_ALLOW:=}"
: "${FIREWALL_NAT_NETS:=}"
: "${FIREWALL_NAT_HOSTS:=}"
: "${FIREWALL_PORT_FORWARD_LIST:=}"
: "${FIREWALL_ALLOW_NETS:=}"
: "${FIREWALL_BLOCK_NETS:=}"
: "${FIREWALL_DEFAULT_FORWARD:=deny}"
: "${FIREWALL_LOG:=on}"
: "${FIREWALL_RELOAD:=auto}"

FW_NAT_NETS=$(sanitize_list "$FIREWALL_NAT_NETS")
FW_NAT_HOSTS=$(sanitize_list "$FIREWALL_NAT_HOSTS")
FW_ALLOW_NETS=$(sanitize_list "$FIREWALL_ALLOW_NETS")
FW_BLOCK_NETS=$(sanitize_list "$FIREWALL_BLOCK_NETS")
FW_FORWARD_ALLOW=$(printf '%s' "$FIREWALL_FORWARD_ALLOW" | tr ',;' ' ')
FW_PORT_FORWARDS=$(printf '%s' "$FIREWALL_PORT_FORWARD_LIST" | tr '\n' ' ')

export FIREWALL_ENABLE FIREWALL_PFCTL FIREWALL_NAT_OUT_IF \
       FIREWALL_DEFAULT_FORWARD FIREWALL_LOG FIREWALL_RELOAD \
       FW_NAT_NETS FW_NAT_HOSTS FW_ALLOW_NETS FW_BLOCK_NETS \
       FW_FORWARD_ALLOW FW_PORT_FORWARDS FIREWALL_LOG_FILE
