#!/bin/sh
# -------------------------------------------------------------------
# pfSense Management Interface Context Script (for OpenNebula)
# Author: shaman edition (final stable IP-based version)
# -------------------------------------------------------------------
# Controls management interface settings via OpenNebula context vars:
#   MGMT_ENABLE=YES|NO
#   MGMT_IF=lan|wan|optN
# -------------------------------------------------------------------

: "${MGMT_ENABLE:=NO}"
: "${MGMT_IF:=lan}"
LOG_FILE="/var/log/context-mgmt.log"

log() {
    printf '%s [MGMT] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG_FILE"
}

apply_php() {
    /usr/local/bin/php -r "$1"
}

log "Starting Management Interface Context (MGMT_IF=${MGMT_IF}, MGMT_ENABLE=${MGMT_ENABLE})"

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
done

if [ "$REAL_IF" = "$MGMT_IF" ]; then
    log "Error: Unable to resolve real interface for ${MGMT_IF}"
    exit 1
fi

log "Resolved pfSense interface ${MGMT_IF} -> ${REAL_IF}"

# -------------------------------------------------------------------
# MAIN LOGIC
# -------------------------------------------------------------------
if [ "$MGMT_ENABLE" = "YES" ]; then
    log "Enabling management interface $MGMT_IF ($REAL_IF)"

    # 1️⃣ Убираем gateway (исключаем из маршрутизации)
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

    # 2️⃣ Добавляем firewall правила, используя IP интерфейса
    log "Adding [MGMT] firewall rules for $MGMT_IF"
    apply_php "
        require_once('filter.inc');
        require_once('interfaces.inc');

        \$if = '${MGMT_IF}';
        \$config = parse_config(true);

        // Получаем IP интерфейса (IPv4)
        \$ip = get_interface_ip(\$if);
        if (empty(\$ip)) {
            \$ip = '127.0.0.1'; // fallback
        }

        // Удаляем старые [MGMT]-правила
        if (isset(\$config['filter']['rule'])) {
            \$config['filter']['rule'] = array_values(array_filter(
                \$config['filter']['rule'],
                function (\$r) { return !isset(\$r['descr']) || strpos(\$r['descr'], '[MGMT]') === false; }
            ));
        } else {
            \$config['filter']['rule'] = array();
        }

        // Правило 1: Разрешить ICMP (ping)
        \$rule_icmp = array(
            'type' => 'pass',
            'interface' => \$if,
            'ipprotocol' => 'inet',
            'protocol' => 'icmp',
            'source' => array('network' => \$if),
            'destination' => array('address' => \$ip),
            'descr' => '[MGMT] Allow ICMP (ping)',
        );

        // Правило 2: Разрешить TCP (22,443)
        \$rule_tcp = array(
            'type' => 'pass',
            'interface' => \$if,
            'ipprotocol' => 'inet',
            'protocol' => 'tcp',
            'source' => array('network' => \$if),
            'destination' => array('address' => \$ip),
            'destinationport' => array('22', '443'),
            'descr' => '[MGMT] Allow SSH/WebGUI',
        );

        // Правило 3: Блокировать всё остальное
        \$rule_block = array(
            'type' => 'block',
            'interface' => \$if,
            'ipprotocol' => 'inet',
            'source' => array('network' => \$if),
            'destination' => array('any' => ''),
            'descr' => '[MGMT] Block all other traffic',
        );

        // Добавляем правила
        \$config['filter']['rule'][] = \$rule_icmp;
        \$config['filter']['rule'][] = \$rule_tcp;
        \$config['filter']['rule'][] = \$rule_block;

        write_config('[MGMT] Added management firewall rules');
        filter_configure();
    "

    log "Management interface $MGMT_IF configured successfully"

else
    log "Disabling management interface $MGMT_IF"

    # Удаляем firewall правила [MGMT]
    log "Removing [MGMT] firewall rules"
    apply_php "
        require_once('filter.inc');
        \$config = parse_config(true);
        if (isset(\$config['filter']['rule'])) {
            \$config['filter']['rule'] = array_values(array_filter(
                \$config['filter']['rule'],
                function (\$r) { return !isset(\$r['descr']) || strpos(\$r['descr'], '[MGMT]') === false; }
            ));
            write_config('[MGMT] Removed management rules');
            filter_configure();
        }
    "

    # Убираем gateway, если остался
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
