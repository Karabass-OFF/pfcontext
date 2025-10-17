#!/bin/sh


configure_interfaces_by_mac() {
    # --- СЕТИ / ИНТЕРФЕЙСЫ ---------------------------------------------------
    iface_type_changed=false
    added_if_count=0
    # Проверяем, есть ли новые ETHx_* переменные против текущего config.xml
    ctx_if_count=$(set | grep -oE '^ETH(ERNET)?[0-9]+_MAC' | sort -u | wc -l | awk '{print $1}')
    xml_if_count=$(xml sel -t -v "count(//interfaces/*)" "$xml_file" 2>/dev/null || echo 0)
    if [ "$ctx_if_count" -gt "$xml_if_count" ]; then
        iface_type_changed=true
        echo "$(date) [context-interfaces] Detected $ctx_if_count ETHx entries > $xml_if_count XML entries — rebuild required" >> "$LOG"
    fi
    # Проверяем несоответствия по описанию
    for var in $(set | grep -oE '^ETH(ERNET)?[0-9]+_TYPE' | sort -u); do
        idx=$(echo "$var" | grep -oE '[0-9]+')
        ctx_mac=$(get_ctx_var "$idx" "MAC")
        want_type=$(get_ctx_var "$idx" "TYPE")
        [ -n "$ctx_mac" ] || continue
        [ -n "$want_type" ] || continue
        # Ищем системный интерфейс с таким MAC
        sys_if=$(ifconfig -l | tr ' ' '\n' | while read -r i; do # перебираем все интерфейсы
            sys_mac=$(ifconfig "$i" | awk '/ether/{print $2}')
            [ "$sys_mac" = "$ctx_mac" ] && echo "$i" && break
        done)
        [ -n "$sys_if" ] || continue
        current_descr=$(ifconfig "$sys_if" | awk -F: '/description/{print $2}' | xargs)
        case "$want_type" in
            lan) want_descr="LAN" ;;
            wan) want_descr="WAN" ;;
            *)   want_descr=$(echo "$want_type" | tr '[:lower:]' '[:upper:]') ;;
        esac
        if [ "$current_descr" != "$want_descr" ]; then
            echo "$(date) [context-interfaces] ${var} mismatch for $sys_if (MAC=$ctx_mac): want=$want_descr, have=$current_descr" >> "$LOG"
            iface_type_changed=true
        fi
    done
    # Подсчитываем количество явных запросов LAN/WAN, чтобы авто-назначение
    # не перехватывало их, если соответствующий интерфейс встретится позже
    lan_explicit_count=$(set | grep -oE '^ETH(ERNET)?[0-9]+_TYPE' | sort -u | while read -r var; do
        idx=$(echo "$var" | grep -oE '[0-9]+')
        want=$(get_ctx_var "$idx" "TYPE" | tr '[:upper:]' '[:lower:]')
        [ "${want}" = "lan" ] && echo 1
    done | wc -l | awk '{print $1}')
    # Количество явных запосов WAN
    wan_explicit_count=$(set | grep -oE '^ETH(ERNET)?[0-9]+_TYPE' | sort -u | while read -r var; do
        idx=$(echo "$var" | grep -oE '[0-9]+')
        want=$(get_ctx_var "$idx" "TYPE" | tr '[:upper:]' '[:lower:]')
        [ "${want}" = "wan" ] && echo 1
    done | wc -l | awk '{print $1}')
    lan_pending=$lan_explicit_count
    wan_pending=$wan_explicit_count
    # Если есть новые интерфейсы или изменились типы, перенастраиваем
    # все интерфейсы заново (удаляем все из config.xml и добавляем по новой)
    if [ -f "$PID" ] || [ "$iface_type_changed" = "true" ]; then
        xml ed -L -d "//interfaces/*" "$backup_xml_file"
        sys_ifaces=$(ifconfig -l)
        lan_assigned=false
        wan_assigned=false
        next_opt=1
        used_networks=""
        # Перебираем системные интерфейсы
        for iface in $sys_ifaces; do
            sys_mac=$(ifconfig "$iface" | awk '/ether/ {print $2}')
            [ -n "$sys_mac" ] || continue
            # Ищем соответствие MAC в контекстных переменных
            for var in $(set | grep -oE '^ETH(ERNET)?[0-9]+_MAC' | sort -u); do
                ctx_mac=$(eval "printf '%s' \"\${$var:-}\"")
                [ -n "$ctx_mac" ] || continue
                # Совпало — настраиваем
                if [ "$ctx_mac" = "$sys_mac" ]; then
                    idx=$(echo "$var" | grep -oE '[0-9]+')
                    ip_addr=$(get_ctx_var "$idx" "IP")
                    mask=$(get_ctx_var "$idx" "MASK")
#                    gw=$(get_ctx_var "$idx" "GATEWAY")
                    iface_type=$(get_ctx_var "$idx" "TYPE")
                    # Определяем тип интерфейса
                    if [ -n "$iface_type" ]; then
                        lower_type=$(echo "$iface_type" | tr '[:upper:]' '[:lower:]')
                        case "$lower_type" in
                            lan)
                                # Явный запрос LAN
                                if [ "$lan_pending" -gt 0 ]; then
                                    lan_pending=$((lan_pending - 1))
                                fi
                                # Если LAN еще не назначен, назначаем
                                if [ "$lan_assigned" = "false" ]; then
                                    network="lan"
                                    desc="LAN"
                                    lan_assigned=true
                                    used_networks="$used_networks $network"
                                else # Если LAN уже назначен, выдаем OPT
                                    echo "$(date) [context-interfaces] Duplicate LAN request for $iface (MAC=$ctx_mac) — assigning OPT" >> "$LOG"
                                    candidate="opt$next_opt"
                                    # Ищем свободный OPT
                                    while echo "$used_networks" | tr ' ' '\n' | grep -qx "$candidate"; do
                                        next_opt=$((next_opt + 1))
                                        candidate="opt$next_opt"
                                    done
                                    network="$candidate"
                                    used_networks="$used_networks $network"
                                    next_opt=$((next_opt + 1))
                                    desc="$(echo "$network" | tr '[:lower:]' '[:upper:]')"
                                fi
                                ;;
                            wan)
                                # Явный запрос WAN
                                if [ "$wan_pending" -gt 0 ]; then
                                    wan_pending=$((wan_pending - 1))
                                fi
                                # Если WAN еще не назначен, назначаем
                                if [ "$wan_assigned" = "false" ]; then
                                    network="wan"
                                    desc="WAN"
                                    wan_assigned=true
                                    used_networks="$used_networks $network"
                                else # Если WAN уже назначен, выдаем OPT
                                    echo "$(date) [context-interfaces] Duplicate WAN request for $iface (MAC=$ctx_mac) — assigning OPT" >> "$LOG"
                                    candidate="opt$next_opt"
                                    # Ищем свободный OPT
                                    while echo "$used_networks" | tr ' ' '\n' | grep -qx "$candidate"; do
                                        next_opt=$((next_opt + 1))
                                        candidate="opt$next_opt"
                                    done
                                    network="$candidate"
                                    used_networks="$used_networks $network"
                                    next_opt=$((next_opt + 1))
                                    desc="$(echo "$network" | tr '[:lower:]' '[:upper:]')"
                                fi
                                ;;
                            opt[0-9]*)
                                # Запрос OPTx
                                candidate="$lower_type"
                                if echo "$used_networks" | tr ' ' '\n' | grep -qx "$candidate"; then
                                    candidate="opt$next_opt"
                                    # Ищем свободный OPT
                                    while echo "$used_networks" | tr ' ' '\n' | grep -qx "$candidate"; do
                                        next_opt=$((next_opt + 1))
                                        candidate="opt$next_opt"
                                    done
                                    network="$candidate"
                                    desc="$(echo "$network" | tr '[:lower:]' '[:upper:]')"
                                    used_networks="$used_networks $network"
                                    next_opt=$((next_opt + 1))
                                else # OPTx свободен, назначаем его
                                    network="$candidate"
                                    desc="$(echo "$network" | tr '[:lower:]' '[:upper:]')"
                                    used_networks="$used_networks $network"
                                    opt_index=$(echo "$candidate" | sed 's/^opt//')
                                    # Обновляем next_opt, если нужно
                                    if echo "$opt_index" | grep -Eq '^[0-9]+$'; then
                                        opt_index=$((opt_index + 1))
                                        if [ "$opt_index" -gt "$next_opt" ]; then
                                            next_opt="$opt_index"
                                        fi
                                    fi
                                fi
                                ;;
                            *)
                                # Неизвестный тип — выдаем OPT
                                candidate="opt$next_opt"
                                # Ищем свободный OPT
                                while echo "$used_networks" | tr ' ' '\n' | grep -qx "$candidate"; do
                                    next_opt=$((next_opt + 1))
                                    candidate="opt$next_opt"
                                done
                                network="$candidate"
                                used_networks="$used_networks $network"
                                next_opt=$((next_opt + 1))
                                desc="$(echo "$network" | tr '[:lower:]' '[:upper:]')"
                                ;;
                        esac
                    else # Тип не указан — выдаем следующий свободный OPT
                        candidate="opt$next_opt"
                        # Ищем свободный OPT
                        while echo "$used_networks" | tr ' ' '\n' | grep -qx "$candidate"; do
                            next_opt=$((next_opt + 1))
                            candidate="opt$next_opt"
                        done
                        network="$candidate"
                        used_networks="$used_networks $network"
                        next_opt=$((next_opt + 1))
                        desc="$(echo "$network" | tr '[:lower:]' '[:upper:]')"
                    fi
                    # Конфигурируем интерфейс
                    if [ -n "$ip_addr" ] && [ -n "$mask" ]; then
                        prefix=$(php -r "echo substr_count(decbin(ip2long('$mask')), '1');")
                        ifconfig "$iface" inet "$ip_addr" netmask "$mask" description "$desc"
                        ifconfig "$iface" ether "$ctx_mac"
                        echo "$(date) [context-interfaces] Added $iface → $desc ($ip_addr/$prefix)" >> "$LOG"
                        added_if_count=$((added_if_count + 1))
                        # Добавляем интерфейс в config.xml
                        xml ed -L \
                            -s "//interfaces" -t elem -n "$network" -v "" \
                            -s "//interfaces/$network" -t elem -n "descr" -v "$desc" \
                            -s "//interfaces/$network" -t elem -n "enable" -v "YES" \
                            -s "//interfaces/$network" -t elem -n "ipaddr" -v "$ip_addr" \
                            -s "//interfaces/$network" -t elem -n "if" -v "$iface" \
                            -s "//interfaces/$network" -t elem -n "spoofmac" -v "$ctx_mac" \
                            -s "//interfaces/$network" -t elem -n "subnet" -v "$prefix" \
                            "$backup_xml_file"
                        # Защита от проблем с XML-парсером pfSense (CDATA и пустой enable)
                        sed -i '' \
                            -e "s|<descr>$desc</descr>|<descr><![CDATA[$desc]]></descr>|g" \
                            -e 's|<enable>YES</enable>|<enable></enable>|g' \
                            "$backup_xml_file"
                    fi
                fi
            done
        done
    fi
    echo "$(date) [context-interfaces] Total interfaces configured: $added_if_count" >> "$LOG"
    # --- /СЕТИ ---------------------------------------------------------------
}
