# shellcheck shell=sh disable=SC2034,SC2154

# Если BGP включен, удаляем маршрут по умолчанию, чтобы BGP управлял маршрутом самостоятельно
# BGP_ENABLE=YES|NO (по умолчанию NO)
if [ "${BGP_ENABLE}" = "YES" ] ; then # Если BGP включен, то удаляем маршрут
    echo "$(date) [context:pfctl.sh] BGP is enabled, removing default route: $WAN_GATEWAY because BGP will manage it" >> "$LOG"
    route delete default >/dev/null 2>&1
    # Удаляем старый шлюз из config.xml, если он есть
    xml ed -L -d "//gateways/gateway_item[name='WANGW']" "$backup_xml_file"
    xml ed -L -d "//interfaces//gateway[text()='WANGW']" "$backup_xml_file"
    xml ed -L -d "//gateways/defaultgw4[text()='WANGW']" "$backup_xml_file"
fi
# Отключаем/Включаем private networks для WAN
if [ -n "$BLOCK_PRIVATE_NETWORKS" ] && [ "$BLOCK_PRIVATE_NETWORKS" = "YES" ]; then
     xml ed -L \
        -s "//interfaces/$network" -t elem -n "blockpriv" -v "" \
        "$backup_xml_file"
    echo "$(date) [context:pfctl.sh] BLOCK_PRIVATE_NETWORKS ($BLOCK_PRIVATE_NETWORKS)" >> "$LOG"
else
    xml ed -L \
        -d "//interfaces/$network/blockpriv" \
        "$backup_xml_file"
    echo "$(date) [context:pfctl.sh] No BLOCK_PRIVATE_NETWORKS ($BLOCK_PRIVATE_NETWORKS)" >> "$LOG"
fi
# Отключаем/Включаем bogon networks для WAN
if [ -n "$BLOCK_BOGON_NETWORKS" ] && [ "$BLOCK_BOGON_NETWORKS" = "YES" ]; then
    xml ed -L \
        -s "//interfaces/$network" -t elem -n "blockbogons" -v "" \
        "$backup_xml_file"
    echo "$(date) [context:pfctl.sh-network] BLOCK_BOGON_NETWORKS ($BLOCK_BOGON_NETWORKS)" >> "$LOG"
else
    xml ed -L \
        -d "//interfaces/$network/blockbogons" \
        "$backup_xml_file"
    echo "$(date) [context:pfctl.sh] No BLOCK_BOGON_NETWORKS ($BLOCK_BOGON_NETWORKS)" >> "$LOG"
fi

# Если есть изменения в секции interfaces, ставим флаг на перезагрузку интерфейсов
# RC_RELOAD_IFACE=YES|NO 
hash1="$(xml sel -t -c "//interfaces" "$xml_file" | xml fo -n -o | tr -d '\n' | md5)"
hash2="$(xml sel -t -c "//interfaces" "$backup_xml_file" | xml fo -n -o | tr -d '\n' | md5)"
if [ "$hash1" != "$hash2" ]; then
   { export RC_RELOAD_IFACE="YES"
     echo "$(date) [context:pfctl.sh] Interfaces section changed, need to reload interfaces set RC_RELOAD_IFACE=YES"
     echo "$(date) [context:pfctl.sh] Old interfaces config hash check only WAN: $hash1"
     echo "$(date) [context:pfctl.sh] New interfaces config hash check only WAN: $hash2"
     echo "$(date) [context:pfctl.sh] Set RC_RELOAD_IFACE=${RC_RELOAD_IFACE}" 
    }>> "$LOG"
    
    
else 
    printf "%s [context:pfctl.sh] Interfaces section unchanged config hash check only WAN\n 1. Old interfaces config hash: %s\n 2. New interfaces config hash: %s\n" \
  "$(date)" "$hash1" "$hash2" >> "$LOG"

fi
