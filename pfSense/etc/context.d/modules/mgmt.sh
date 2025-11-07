#!/bin/sh
# -------------------------------------------------------------------
# pfSense Management Interface Context Script (OpenNebula compatible)
# Author: shaman edition — v3.2
# -------------------------------------------------------------------
# Context vars:
#   MGMT_ENABLE=YES|NO
#   MGMT_IF=lan|wan|optN         # Где расположен управляемый IP (назначение)
#   MGMT_PORT=22,443,80,8443     # Порты GUI/SSH и т.п.
#   MGMT_SRC=...                 # ОТКУДА пускать. Форматы:
#       - lan|wan|ipsec
#       - CIDR (10.11.11.0/24, 203.0.113.5/32)
#       - iface:CIDR|net|any  (напр. ipsec:10.11.11.0/24, lan:net, wan:any)
#   MGMT_SRC_DEFAULT_IF=lan    # если MGMT_SRC содержит «голый» CIDR без iface
# -------------------------------------------------------------------
: "${MGMT_ENABLE:=YES}"
: "${MGMT_IF:=lan}"
: "${MGMT_PORT:=22,80,443}"
: "${MGMT_SRC:=lan:192.168.0.0/16}"
: "${MGMT_SRC_DEFAULT_IF:=lan}"

LOG_FILE="/var/log/context.log"
SCRIPT_VERSION="$(cat /etc/context.d/VERSION 2>/dev/null || echo "unknown")"

export MGMT_ENABLE MGMT_IF MGMT_PORT MGMT_SRC MGMT_SRC_DEFAULT_IF

log() {
  printf '%s [context-MGMT] %s\n' "$(date)" "$*" >> "$LOG_FILE"
}

apply_php() {
  /usr/local/bin/php -r "$1" 2>&1 | while IFS= read -r line; do
    printf '%s [context-MGMT][php] %s\n' "$(date)" "$line" >> "$LOG_FILE"
  done
}

log "Starting Management Interface Context (version=${SCRIPT_VERSION}, IF=${MGMT_IF}, ENABLE=${MGMT_ENABLE}, PORT=${MGMT_PORT}, SRC=${MGMT_SRC}, path=$(realpath "$0"))"

CONF_PATH="$(/usr/local/bin/php -r "require_once(\"config.inc\"); global \$g; echo (\$g[\"conf_path\"] ?? \"/conf\");" 2>/dev/null)"
[ -z "$CONF_PATH" ] && CONF_PATH="/conf"
log "Detected conf path: ${CONF_PATH}/config.xml"

# ---- resolve real if (для справки в логах; для правил достаточно логического имени) ----
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
  log "Warning: Unable to resolve real interface for ${MGMT_IF} (continuing)"
else
  log "Resolved pfSense interface ${MGMT_IF} -> ${REAL_IF}"
fi

# ---- helpers ----
php_ensure_aliases_array="
require_once(\"config.inc\");
global \$config;
if (!isset(\$config[\"aliases\"]) || !is_array(\$config[\"aliases\"])) { \$config[\"aliases\"] = []; }
if (!isset(\$config[\"aliases\"][\"alias\"]) || !is_array(\$config[\"aliases\"][\"alias\"])) { \$config[\"aliases\"][\"alias\"] = []; }
"

php_apply_aliases_and_filter='
require_once("filter.inc");
if (function_exists("filter_generate_aliases_config")) {
  filter_generate_aliases_config();
}
filter_configure();
'

if [ "$MGMT_ENABLE" = "YES" ]; then
  log "=== Enabling management interface $MGMT_IF ==="

  # 1) отключить anti-lockout
  log "Disabling webConfigurator anti-lockout rule (set noantilockout=yes)"
  apply_php "
    require_once('config.inc');
    global \$config;
    \$config['system']['webgui'] = \$config['system']['webgui'] ?? [];
    \$config['system']['webgui']['noantilockout'] = 'yes';
    write_config('[MGMT] Disable anti-lockout (set yes)');
  "

  # 2) убрать gateway на MGMT_IF
  log "Removing gateway from $MGMT_IF"
  apply_php "
    require_once('config.inc');
    require_once('interfaces.inc');
    require_once('system.inc');
    global \$config;
    \$if='${MGMT_IF}';
    if (isset(\$config['interfaces'][\$if]['gateway'])) {
      unset(\$config['interfaces'][\$if]['gateway']);
      write_config('[MGMT] Remove gateway from '.\$if);
      system_routing_configure();
    }
  "

  # 3) alias MGMT_PORTS
  log "Updating alias [MGMT_PORTS] with ports: ${MGMT_PORT}"
  apply_php "
    require_once('util.inc');
    ${php_ensure_aliases_array}
    global \$config;

    \$alias = 'MGMT_PORTS';
    \$ports = array_filter(array_map('trim', explode(',', '${MGMT_PORT}')));

    // Удалить старый MGMT_PORTS
    \$config['aliases']['alias'] = array_values(array_filter(
      \$config['aliases']['alias'],
      function(\$a){ return !is_array(\$a) || (\$a['name'] ?? '') !== 'MGMT_PORTS'; }
    ));

    // Добавить заново
    \$config['aliases']['alias'][] = [
      'name'=>\$alias,
      'type'=>'port',
      'address'=>implode(' ', \$ports),
      'descr'=>'[MGMT] Management Ports'
    ];

    write_config('[MGMT] Updated alias MGMT_PORTS');
    mark_subsystem_dirty('aliases');
  "

  # 4) правила FW по источникам MGMT_SRC (+ per-iface BLOCK any→mgmtIP)
  log "Adding [MGMT] firewall rules from sources: ${MGMT_SRC}"
  apply_php "
    require_once('config.inc');
    require_once('filter.inc');
    require_once('interfaces.inc');
    global \$config;

    \$mgmtIf   = '${MGMT_IF}';
    \$mgmtIp   = get_interface_ip(\$mgmtIf) ?: '127.0.0.1';
    \$srcSpec  = getenv('MGMT_SRC') ?: 'lan';
    \$defIf    = getenv('MGMT_SRC_DEFAULT_IF') ?: 'ipsec';

    // удалить старые [MGMT]-правила и дефолтные allow LAN/WAN
    \$config['filter']['rule'] = array_values(array_filter(\$config['filter']['rule'] ?? [], function(\$r) use (\$mgmtIf) {
    // если нет descr — оставляем
    if (!isset(\$r['descr'])) return true;

    \$descr = strtolower(\$r['descr']);
    // удалить все [MGMT] и default allow на том же интерфейсе
    if (strpos(\$descr, '[mgmt]') !== false) return false;
    if (strpos(\$descr, 'default allow') !== false && (\$r['interface'] ?? '') === \$mgmtIf) return false;
    if (strpos(\$descr, 'anti-lockout') !== false && (\$r['interface'] ?? '') === \$mgmtIf) return false;
    return true;
}));

    // разобрать MGMT_SRC
    \$entries   = array_filter(array_map('trim', explode(',', \$srcSpec)));
    \$rules     = [];
    \$ifUsedMap = [];  // интерфейсы, на которых будем ставить итоговый BLOCK any→mgmtIP

    foreach (\$entries as \$e) {
      \$iface = '';
      \$net   = '';

      if (strpos(\$e, ':') !== false) {
        list(\$iface, \$net) = array_map('trim', explode(':', \$e, 2));
      } else {
        if (in_array(\$e, ['lan','wan','ipsec'])) {
          \$iface = \$e; \$net = 'net';
        } else {
          // голый CIDR/хост — повесим на MGMT_SRC_DEFAULT_IF
          \$iface = \$defIf; \$net = \$e;
        }
      }
      if (\$iface === '') { continue; }
      \$ifUsedMap[\$iface] = true;

      // source
      if (\$net === 'net') {
        \$src = ['network' => \$iface];       // «LAN net», «WAN net», «IPsec net»
      } elseif (\$net === 'any') {
        \$src = ['any' => ''];
      } else {
        \$src = ['address' => \$net];         // CIDR/host/alias
      }

      // allow ICMP (ping) на интерфейсе-источнике
      \$rules[] = [
        'type'=>'pass','interface'=>\$iface,'ipprotocol'=>'inet','protocol'=>'icmp',
        'source'=>\$src,'destination'=>['address'=>\$mgmtIp],
        'descr'=>sprintf('[MGMT] Allow ICMP to %s from %s:%s', \$mgmtIp, \$iface, \$net)
      ];
      // allow TCP mgmt ports на интерфейсе-источнике
      \$rules[] = [
        'type'=>'pass','interface'=>\$iface,'ipprotocol'=>'inet','protocol'=>'tcp',
        'source'=>\$src,'destination'=>['address'=>\$mgmtIp,'port'=>'MGMT_PORTS'],
        'descr'=>sprintf('[MGMT] Allow mgmt ports (%s) to %s from %s:%s', '${MGMT_PORT}', \$mgmtIp, \$iface, \$net)
      ];
    }

    // Итоговый BLOCK: на каждом задействованном интерфейсе — блокировать ЛЮБОЙ источник к mgmt IP
    foreach (array_keys(\$ifUsedMap) as \$iface) {
      \$rules[] = [
        'type'=>'block','interface'=>\$iface,'ipprotocol'=>'inet', /* protocol=any */
        'source'=>['any'=>''],'destination'=>['address'=>\$mgmtIp],
        'descr'=>sprintf('[MGMT] Block all other sources to %s on %s', \$mgmtIp, \$iface),
        'quick'=>'yes'
      ];
    }

    // Добавить все правила в конфиг (без включения лога)
    foreach (\$rules as \$r) { \$config['filter']['rule'][] = \$r; }

    write_config('[MGMT] Added management firewall rules (per-iface block any→mgmtIP)');
  "

  # 5) применить конфиг
  log "Applying aliases + filter"
  apply_php "${php_apply_aliases_and_filter}"

  log "Management interface $MGMT_IF configured successfully"

else
  log "=== Disabling management interface $MGMT_IF ==="

  # 1) вернуть anti-lockout
  log "Re-enabling webConfigurator anti-lockout rule (remove noantilockout)"
  apply_php "
    require_once('config.inc');
    global \$config;
    if (isset(\$config['system']['webgui']['noantilockout'])) {
      unset(\$config['system']['webgui']['noantilockout']);
      write_config('[MGMT] Re-enable anti-lockout (remove key)');
    }
  "

  # 2) удалить [MGMT]-правила
  log "Removing [MGMT] firewall rules"
  apply_php "
    require_once('config.inc'); require_once('filter.inc');
    global \$config;
    if (isset(\$config['filter']['rule'])) {
      \$config['filter']['rule'] = array_values(array_filter(\$config['filter']['rule'],
        function(\$r){ return !isset(\$r['descr']) || strpos(\$r['descr'],'[MGMT]')===false; }
      ));
      write_config('[MGMT] Removed management rules');
    }
  "

  # 3) удалить алиас MGMT_PORTS
  log "Removing alias [MGMT_PORTS]"
  apply_php "
    require_once('config.inc'); require_once('util.inc');
    global \$config;
    if (!isset(\$config['aliases']) || !is_array(\$config['aliases'])) { \$config['aliases'] = []; }
    if (isset(\$config['aliases']['alias']) && is_array(\$config['aliases']['alias'])) {
      \$config['aliases']['alias'] = array_values(array_filter(
        \$config['aliases']['alias'],
        function(\$a){ return !is_array(\$a) || (\$a['name'] ?? '') !== 'MGMT_PORTS'; }
      ));
      write_config('[MGMT] Removed alias MGMT_PORTS');
      mark_subsystem_dirty('aliases');
    }
  "

  # 4) убрать gateway на MGMT_IF (на всякий)
  log "Removing gateway from $MGMT_IF"
  apply_php "
    require_once('config.inc'); require_once('interfaces.inc'); require_once('system.inc');
    global \$config; \$if='${MGMT_IF}';
    if (isset(\$config['interfaces'][\$if]['gateway'])) {
      unset(\$config['interfaces'][\$if]['gateway']);
      write_config('[MGMT] Remove gateway from '.\$if);
      system_routing_configure();
    }
  "

  # 5) применить
  log "Applying aliases + filter"
  apply_php "${php_apply_aliases_and_filter}"

  log "Management interface $MGMT_IF disabled"
fi

log "Context script finished"
return 0
