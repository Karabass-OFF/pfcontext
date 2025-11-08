# shellcheck shell=sh disable=SC2034,SC2154

# Если BGP включен, удаляем маршрут по умолчанию, чтобы BGP управлял маршрутом самостоятельно
# BGP_ENABLE=YES|NO (по умолчанию NO)
if [ "${BGP_ENABLE}" = "YES" ] ; then # Если BGP включен, то удаляем маршрут
    echo "$(date) [context] BGP is enabled, removing default route: $WAN_GATEWAY because BGP will manage it" >> "$LOG"
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
    echo "$(date) [context] BLOCK_PRIVATE_NETWORKS" >> "$LOG"
else
    xml ed -L \
        -d "//interfaces/$network/blockpriv" \
        "$backup_xml_file"
    echo "$(date) [context] No BLOCK_PRIVATE_NETWORKS" >> "$LOG"
fi
# Отключаем/Включаем bogon networks для WAN
if [ -n "$BLOCK_BOGON_NETWORKS" ] && [ "$BLOCK_BOGON_NETWORKS" = "YES" ]; then
    xml ed -L \
        -s "//interfaces/$network" -t elem -n "blockbogons" -v "" \
        "$backup_xml_file"
    echo "$(date) [context-network] BLOCK_BOGON_NETWORKS" >> "$LOG"
else
    xml ed -L \
        -d "//interfaces/$network/blockbogons" \
        "$backup_xml_file"
    echo "$(date) [context] No BLOCK_BOGON_NETWORKS" >> "$LOG"
fi

# Если есть изменения в секции interfaces, ставим флаг на перезагрузку интерфейсов
# RC_RELOAD_IFACE=YES|NO (по умолчанию NO)
hash1="$(xml sel -t -c "//interfaces" "$xml_file" | xml fo -n -o | tr -d '\n' | md5)"
cp "$xml_file" "/root/xml_file"
cp "$backup_xml_file" "/root/backup_xml_file"
hash2="$(xml sel -t -c "//interfaces" "$backup_xml_file" | xml fo -n -o | tr -d '\n' | md5)"
if [ "$hash1" != "$hash2" ]; then
   { echo "$(date) [context] Interfaces section changed, need to reload interfaces set RC_RELOAD_IFACE=YES"
     echo "$(date) [context] Old interfaces config hash: $hash1"
     echo "$(date) [context] New interfaces config hash: $hash2"
    }>> "$LOG"
    RC_RELOAD_IFACE="YES"
fi
# Перезагрузка служб pfSense (если указано в контексте)
if [ "${RC_RELOAD_ALL}" = "YES" ]; then
    # Перезагружаем службы pfSense
   {    /etc/rc.reload_all start
        echo "$(date) [context] pfSense services reloaded"
        pfSsh.php playback restartallwan
        echo "$(date) [context] pfSense services restarted"
    } >>"$LOG" 2>&1
fi
# Перезагрузка интерфейсов pfSense (если указано в контексте)
if [ "${RC_RELOAD_IFACE}" = "YES" ]; then
    echo "$(date) [context]  ${RC_RELOAD_IFACE} or PID file detected $PID" 
    # Перезагружаем интерфейсы pfSense
    {   pfSsh.php playback restartallwan
        echo "$(date) [context] pfSense services restarted"
    } >>"$LOG" 2>&1
fi

# отключение/включение pfSense firewall (pfctl) 
echo "$(date) [context] pfSense firewall switch = ${PFCTL}" >> "$LOG"
if [ -n "${PFCTL:-}" ]; then # если переменная PFCTL указана
    # Приводим значение к нижнему регистру для удобства сравнения   
    _lc_pfctl=$(echo "${PFCTL}" | tr '[:upper:]' '[:lower:]')
    case "$_lc_pfctl" in
        no|0)
            {
                if pfctl -s info 2>/dev/null | grep -qi 'Status: Enabled'; then
                    pfctl -d
                    echo "$(date) [context] pfSense firewall disabled"
                else
                    echo "$(date) [context] pfSense firewall already disabled (pf not enabled)"
                fi
                echo "$$" > /var/run/pfctlcontext.pid
                echo "$(date) [context] Created pid file: /var/run/pfctlcontext.pid"
            } >> "$LOG" 2>&1
            ;;
        yes|1)
            if pfctl -s info | grep -qi 'Status: Disabled'; then
                {
                    echo "$(date) [context] pfSense firewall was disabled, enabling now '${PFCTL}'"
                    rm -rf /var/run/pfctlcontext.pid
                    echo "$(date) [context] Removed pid file: /var/run/pfctlcontext.pid"
                    pfctl -e
                    echo "$(date) [context] pfSense firewall enabled"
                } >> "$LOG" 2>&1
            fi
            ;;
        *)
            echo "$(date) [context] pfSense firewall state unchanged (PFCTL=$_lc_pfctl)" >> "$LOG"
            ;;
    esac
fi
