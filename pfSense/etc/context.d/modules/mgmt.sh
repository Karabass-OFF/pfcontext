#!/bin/sh
# -------------------------------------------------------------------
# pfSense Management Interface Context Script (for OpenNebula)
# Author: shaman edition (final alias-based + safety fix)
# -------------------------------------------------------------------
# Controls management interface settings via OpenNebula context vars:
#   MGMT_ENABLE=YES|NO
#   MGMT_IF=lan|wan|optN
#   MGMT_PORT=22,443,80,8443
# -------------------------------------------------------------------
# Инициализация переменных
: "${MGMT_ENABLE:=NO}"
: "${MGMT_IF:=lan}"
: "${MGMT_PORT:=22,443}"
LOG_FILE="/var/log/context.log"

export MGMT_ENABLE MGMT_IF MGMT_PORT
# функция логирования
log() {
    printf '%s [MGMT] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG_FILE"
}
# функция выполнения PHP-кода
apply_php() {
    /usr/local/bin/php -r "$1"
}
# Начало выполнения скрипта
log "Starting Management Interface Context (MGMT_IF=${MGMT_IF}, MGMT_ENABLE=${MGMT_ENABLE}, MGMT_PORT=${MGMT_PORT})"

# -------------------------------------------------------------------
# Resolve pfSense logical interface name (lan/wan/optX) to real OS IF
# -------------------------------------------------------------------
REAL_IF=$(/usr/local/bin/php -r "
require_once('interfaces.inc');
\$real = get_real_interface('${MGMT_IF}');
echo \$real ?: '${MGMT_IF}';
")

RETRIES=5
while [ "$REAL_IF" = "$MGMT_IF" ] && [ $RETRIES -gt 0 ]; do
    log "Interface mapping not ready yet, retrying... ($RETRIES)"
    sleep 2
    REAL_IF=$(/usr/local/bin/php -r "
        require_once('interfaces.inc');
        \$real = get_real_interface('${MGMT_IF}');
        echo \$real ?: '${MGMT_IF}';
    ")
    RETRIES=$((RETRIES - 1))
    log "Retries left: $RETRIES"
done
# Если не удалось разрешить интерфейс, выходим с ошибкой
if [ "$REAL_IF" = "$MGMT_IF" ]; then
    log "Error: Unable to resolve real interface for ${MGMT_IF}"
    exit 1
fi
# Логируем результат разрешения интерфейса
log "Resolved pfSense interface ${MGMT_IF} -> ${REAL_IF}"

# -------------------------------------------------------------------
# MAIN LOGIC
# -------------------------------------------------------------------
if [ "$MGMT_ENABLE" = "YES" ]; then
    log "Enabling management interface $MGMT_IF ($REAL_IF)"

    # Убираем gateway (исключаем из маршрутизации)
    log "Removing gateway from $MGMT_IF"
    apply_php "
        require_once('interfaces.inc');
        require_once('system.inc');
        \$if = '${MGMT_IF}';
        \$config = parse_config(true);
        if (isset(\$config['interfaces'][\$if]['gateway'])) {
            unset(\$config['interfaces'][\$if]['gateway']);
            write_config('[MGMT] Remove gateway from ' . \$if);
            system_routing_configure();
        }
    "

    # Создаём / обновляем alias MGMT_PORTS
    log "Updating alias [MGMT_PORTS] with ports: ${MGMT_PORT}"
    apply_php "
        require_once('util.inc');
        require_once('filter.inc');
        require_once('interfaces.inc');

        \$alias_name  = 'MGMT_PORTS';
        \$alias_descr = '[MGMT] Management Ports';
        \$ports       = array_map('trim', explode(',', '${MGMT_PORT}'));

        \$config = parse_config(true);

        // гарантируем наличие структуры aliases
        if (!isset(\$config['aliases']) || !is_array(\$config['aliases'])) {
            \$config['aliases'] = array();
        }
        if (!isset(\$config['aliases']['alias']) || !is_array(\$config['aliases']['alias'])) {
            \$config['aliases']['alias'] = array();
        }

        // удаляем старый alias
        \$config['aliases']['alias'] = array_values(array_filter(
            \$config['aliases']['alias'],
            function(\$a) use (\$alias_name) {
                return !is_array(\$a) || (\$a['name'] ?? '') !== \$alias_name;
            }
        ));

        // добавляем новый alias
        \$config['aliases']['alias'][] = array(
            'name'    => \$alias_name,
            'type'    => 'port',
            'address' => implode(' ', \$ports),
            'descr'   => \$alias_descr
        );

        write_config('[MGMT] Updated alias MGMT_PORTS');
        filter_configure();
    "

    # Добавляем firewall правила
    log "Adding [MGMT] firewall rules for $MGMT_IF"
    apply_php "
        require_once('filter.inc');
        require_once('interfaces.inc');

        \$if = '${MGMT_IF}';
        \$config = parse_config(true);

        // получаем IP интерфейса
        \$ip = get_interface_ip(\$if);
        if (empty(\$ip)) {
            \$ip = '127.0.0.1';
        }

        // очищаем старые [MGMT]-правила
        if (isset(\$config['filter']['rule'])) {
            \$config['filter']['rule'] = array_values(array_filter(
                \$config['filter']['rule'],
                function(\$r) { return !isset(\$r['descr']) || strpos(\$r['descr'], '[MGMT]') === false; }
            ));
        } else {
            \$config['filter']['rule'] = array();
        }

        //  ICMP (ping)
        \$rule_icmp = array(
            'type'       => 'pass',
            'interface'  => \$if,
            'ipprotocol' => 'inet',
            'protocol'   => 'icmp',
            'source'     => array('network' => \$if),
            'destination'=> array('address' => \$ip),
            'descr'      => '[MGMT] Allow ICMP (ping)',
        );

        //  TCP (использует alias MGMT_PORTS)
        \$rule_tcp = array(
            'type'       => 'pass',
            'interface'  => \$if,
            'ipprotocol' => 'inet',
            'protocol'   => 'tcp',
            'source'     => array('network' => \$if),
            'destination'=> array(
                'address' => \$ip,
                'port'    => 'MGMT_PORTS'
            ),
            'descr'      => '[MGMT] Allow management ports (' . '${MGMT_PORT}' . ')',
        );

        //  BLOCK всё остальное
        \$rule_block = array(
            'type'       => 'block',
            'interface'  => \$if,
            'ipprotocol' => 'inet',
            'source'     => array('network' => \$if),
            'destination'=> array('any' => ''),
            'descr'      => '[MGMT] Block all other traffic',
        );

        \$config['filter']['rule'][] = \$rule_icmp;
        \$config['filter']['rule'][] = \$rule_tcp;
        \$config['filter']['rule'][] = \$rule_block;

        write_config('[MGMT] Added management firewall rules');
        filter_configure();
    "

    log "Management interface $MGMT_IF configured successfully"

else
    log "Disabling management interface $MGMT_IF"

    # удаляем firewall правила [MGMT]
    log "Removing [MGMT] firewall rules"
    apply_php "
        require_once('filter.inc');
        \$config = parse_config(true);
        if (isset(\$config['filter']['rule'])) {
            \$config['filter']['rule'] = array_values(array_filter(
                \$config['filter']['rule'],
                function(\$r) { return !isset(\$r['descr']) || strpos(\$r['descr'], '[MGMT]') === false; }
            ));
            write_config('[MGMT] Removed management rules');
            filter_configure();
        }
    "

    # удаляем alias
log "Removing alias [MGMT_PORTS]"
apply_php "
    require_once('util.inc');
    require_once('filter.inc');
    require_once('interfaces.inc');
    \$config = parse_config(true);

    // Удаляем alias из конфига
    if (isset(\$config['aliases']['alias']) && is_array(\$config['aliases']['alias'])) {
        \$config['aliases']['alias'] = array_values(array_filter(
            \$config['aliases']['alias'],
            function(\$a) { return !is_array(\$a) || (\$a['name'] ?? '') !== 'MGMT_PORTS'; }
        ));
        write_config('[MGMT] Removed alias MGMT_PORTS');
    }

    // Перегенерируем alias-файлы и правила
    if (function_exists('filter_generate_aliases_config')) {
        filter_generate_aliases_config();
    }
    filter_configure();
"
    # убираем gateway
    apply_php "
        require_once('interfaces.inc');
        require_once('system.inc');
        \$if = '${MGMT_IF}';
        \$config = parse_config(true);
        if (isset(\$config['interfaces'][\$if]['gateway'])) {
            unset(\$config['interfaces'][\$if]['gateway']);
            write_config('[MGMT] Remove gateway from ' . \$if);
            system_routing_configure();
        }
    "

    log "Management interface $MGMT_IF disabled"
fi

log "Context script finished"
exit 0
