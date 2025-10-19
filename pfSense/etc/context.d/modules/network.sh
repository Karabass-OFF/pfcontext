#!/bin/sh

# Functions responsible for applying network-related settings. The functions
# rely on environment variables defined by ContextOnly and the sourced
# context.sh from the ISO.

apply_dns_settings() {
    backup_xml_file="$1"
    log_file="$2"

    all_dns=$(set | grep -oE '^ETH[0-9]+_DNS' | sort -u | while read -r var; do
        eval "echo \${$var:-}"
    done | xargs)

    if [ -n "$all_dns" ]; then
        dns1=$(echo "$all_dns" | awk '{print $1}')
        dns2=$(echo "$all_dns" | awk '{print $NF}')

        echo "$(date) [context-network:apply_dns_settings] Setting DNS: $dns1 $dns2" >> "$log_file"
        : > /etc/resolv.conf
        [ -n "$dns1" ] && echo "nameserver $dns1" >> /etc/resolv.conf
        [ -n "$dns2" ] && echo "nameserver $dns2" >> /etc/resolv.conf

        xml ed -L \
            -u "//system/dnsserver[1]" -v "$dns1" \
            -u "//system/dnsserver[2]" -v "$dns2" \
            -u "//system/dnsallowoverride" -v "" \
            "$backup_xml_file"

        echo "$(date) [context-network:apply_dns_settings] Set DNS: $dns1 $dns2" >> "$log_file"
    fi
}

apply_hostname_setting() {
    backup_xml_file="$1"
    log_file="$2"

    if [ -n "${SET_HOSTNAME:-}" ]; then
        hostname "$SET_HOSTNAME"
        xml ed -L -u "//system/hostname" -v "$SET_HOSTNAME" "$backup_xml_file"
        echo "$(date) [context-network:apply_hostname_setting] Set hostname: $SET_HOSTNAME" >> "$log_file"
    fi
}

update_interface_reload_flag() {
    xml_file="$1"
    backup_xml_file="$2"
    log_file="$3"

    : "${RC_RELOAD_IFACE:=off}"

    hash1="$(xml sel -t -c "//interfaces" "$xml_file" | md5)"
    hash2="$(xml sel -t -c "//interfaces" "$backup_xml_file" | md5)"

    if [ "$hash1" != "$hash2" ]; then
        {
            echo "$(date) [context-network:update_interface_reload_flag] Interfaces section changed, need to reload interfaces"
            echo "$(date) [context-network:update_interface_reload_flag] Old hash: $hash1"
            echo "$(date) [context-network:update_interface_reload_flag] New hash: $hash2"
        } >> "$log_file"
        RC_RELOAD_IFACE="on"
    fi
}

detect_wan_network() {
    log_file="$1"
    WAN_GATEWAY=""
    WAN_NETWORK=""

    for ifeth in $(ifconfig -l); do
        eth_mac=$(ifconfig "$ifeth" | awk '/ether/ {print $2}')
        [ -n "$eth_mac" ] || continue
        if ifconfig "$ifeth" | grep -q 'description: WAN'; then
            echo "$(date) [context-network:detect_wan_network] Found WAN interface $ifeth (MAC=$eth_mac)" >> "$log_file"
            eth=$(set | grep "ETH" | grep -i "$eth_mac" | cut -d "_" -f 1)
            WAN_GATEWAY=$(set | grep "$eth""_GATEWAY=" | cut -d "=" -f 2 | tr -d '"')
            WAN_NETWORK="wan"
            echo "$(date) [context-network:detect_wan_network] Detected WAN_GATEWAY=$WAN_GATEWAY from $eth" >> "$log_file"
        fi
    done
}

apply_wan_gateway() {
    xml_file="$1"
    backup_xml_file="$2"
    log_file="$3"
    current_gw="$4"
    wan_gateway="$5"
    wan_network="$6"

    [ -n "$wan_gateway" ] || return 0
    network="${wan_network:-wan}"

    if [ "$current_gw" != "$wan_gateway" ]; then
        echo "$(date) [context-network:apply_wan_gateway] Current default gateway: ${current_gw:-"(none)"} differs from desired: $wan_gateway — updating route (BGP off)" >> "$log_file"
        route delete default >/dev/null 2>&1
        route add default "$wan_gateway"
        RC_RELOAD_IFACE="on"
        if ! xml sel -t -v "//gateways" "$backup_xml_file" >/dev/null 2>&1; then
            echo "$(date) [context] Gateways section missing — creating one" >> "$log_file"
            xml ed -L -s "//pfsense" -t elem -n "gateways" -v "" "$backup_xml_file"
        fi

        xml ed -L -d "//gateways/gateway_item[name='WANGW']" "$backup_xml_file"
        xml ed -L -d "//interfaces//gateway[text()='WANGW']" "$backup_xml_file"
        xml ed -L -d "//gateways/defaultgw4[text()='WANGW']" "$backup_xml_file"

        xml ed -L \
            -s "//gateways" -t elem -n "gateway_item" -v "" \
            -s "//gateways/gateway_item[last()]" -t elem -n "interface" -v "$network" \
            -s "//gateways/gateway_item[last()]" -t elem -n "gateway" -v "$wan_gateway" \
            -s "//gateways/gateway_item[last()]" -t elem -n "name" -v "WANGW" \
            -s "//gateways/gateway_item[last()]" -t elem -n "descr" -v "Default IPv4 Gateway" \
            -s "//gateways/gateway_item[last()]" -t elem -n "defaultgw4" -v "yes" \
            -s "//gateways/gateway_item[last()]" -t elem -n "weight" -v "1" \
            -u "//gateways/defaultgw4" -v "WANGW" \
            "$backup_xml_file"

        if xml sel -t -v "//interfaces/$network/gateway" "$backup_xml_file" >/dev/null 2>&1; then
            xml ed -L -u "//interfaces/$network/gateway" -v "WANGW" "$backup_xml_file"
        else
            xml ed -L -s "//interfaces/$network" -t elem -n "gateway" -v "WANGW" "$backup_xml_file"
        fi
    else
        echo "$(date) [context-network:apply_wan_gateway] Current default gateway: $current_gw matches desired: $wan_gateway — no change needed" >> "$log_file"
    fi
}

handle_bgp_default_route() {
    backup_xml_file="$1"
    log_file="$2"
    wan_gateway="$3"

    if [ "${BGP_ENABLE}" = "YES" ]; then
        echo "$(date) [context-network:handle_bgp_default_route] BGP is enabled, removing default route: $wan_gateway because BGP will manage it" >> "$log_file"
        route delete default >/dev/null 2>&1
        xml ed -L -d "//gateways/gateway_item[name='WANGW']" "$backup_xml_file"
        xml ed -L -d "//interfaces//gateway[text()='WANGW']" "$backup_xml_file"
        xml ed -L -d "//gateways/defaultgw4[text()='WANGW']" "$backup_xml_file"
        xml ed -L -d "//system/gateway" "$backup_xml_file"
        RC_RELOAD_IFACE="on"
    fi
}

apply_wan_filters() {
    backup_xml_file="$1"
    log_file="$2"
    network="$3"

    [ -n "$network" ] || return 0

    if [ -n "$BLOCK_PRIVATE_NETWORKS" ] && [ "$BLOCK_PRIVATE_NETWORKS" = "on" ]; then
        xml ed -L \
            -s "//interfaces/$network" -t elem -n "blockbogons" -v "" \
            "$backup_xml_file"
        echo "$(date) [context-network:apply_wan_filters] BLOCK_PRIVATE_NETWORKS" >> "$log_file"
    else
        xml ed -L \
            -d "//interfaces/$network/blockbogons" \
            "$backup_xml_file"
        echo "$(date) [context-network:apply_wan_filters] No BLOCK_PRIVATE_NETWORKS" >> "$log_file"
    fi

    if [ -n "$BLOCK_BOGON_NETWORKS" ] && [ "$BLOCK_BOGON_NETWORKS" = "on" ]; then
        xml ed -L \
            -s "//interfaces/$network" -t elem -n "blockpriv" -v "" \
            "$backup_xml_file"
        echo "$(date) [context-network:apply_wan_filters] BLOCK_BOGON_NETWORKS" >> "$log_file"
    else
        xml ed -L \
            -d "//interfaces/$network/blockpriv" \
            "$backup_xml_file"
        echo "$(date) [context-network:apply_wan_filters] No BLOCK_BOGON_NETWORKS" >> "$log_file"
    fi
}

restart_interfaces_if_requested() {
    log_file="$1"
    pid_file="$2"
    echo "$(date) [context-network:restart_interfaces_if_requested] RC_RELOAD_IFACE=${RC_RELOAD_IFACE:-"EMPTY"} PID file=$pid_file" >> "$log_file"
    if [ "${RC_RELOAD_IFACE}" = "on" ]; then
        echo "$(date) [context-network:restart_interfaces_if_requested]  ${RC_RELOAD_IFACE} or PID file detected $pid_file" >> "$log_file"
        {
            pfSsh.php playback restartallwan
            echo "$(date) [context-network:restart_interfaces_if_requested] pfSense services restarted"
        } >> "$log_file" 2>&1
    fi
}

apply_pfctl_state() {
    log_file="$1"

    echo "$(date) [context-network:apply_pfctl_state] pfSense firewall switch = ${PFCTL}" >> "$log_file"
    if [ -n "${PFCTL:-}" ]; then
        _lc_pfctl=$(echo "${PFCTL}" | tr '[:upper:]' '[:lower:]')
        case "$_lc_pfctl" in
            no|off|0|false|disabled)
                {
                    pfctl -d
                    echo "$(date) [context] pfSense firewall disabled"
                } >> "$log_file" 2>&1
                ;;
            yes|on|1|true|enabled)
                if pfctl -s info | grep -q 'Status: Disabled'; then
                    {
                        echo "$(date) [context] pfSense firewall was disabled, enabling now '${PFCTL}'"
                        pfctl -e
                    } >> "$log_file" 2>&1
                fi
                ;;
            *)
                echo "$(date) [context] pfSense firewall state unchanged (PFCTL=$_lc_pfctl)" >> "$log_file"
                ;;
        esac
    fi
}
