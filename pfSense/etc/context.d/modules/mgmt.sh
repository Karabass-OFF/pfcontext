#!/bin/sh
# -------------------------------------------------------------------
# pfSense Management Interface Context Script (OpenNebula compatible)
# Author: shaman edition — final v3.1
# -------------------------------------------------------------------
# Context vars:
#   MGMT_ENABLE=YES|NO
#   MGMT_IF=lan|wan|optN
#   MGMT_PORT=22,443,80,8443
# -------------------------------------------------------------------

: "${MGMT_ENABLE:=NO}"
: "${MGMT_IF:=lan}"
: "${MGMT_PORT:=22,443}"
LOG_FILE="/var/log/context.log"
SCRIPT_VERSION="$(cat /etc/context.d/VERSION 2>/dev/null || echo "unknown")"

export MGMT_ENABLE MGMT_IF MGMT_PORT

log() {
  printf '%s [context-MGMT] %s\n' "$(date)" "$*" >> "$LOG_FILE"
}

# Проглатываем stdout/stderr PHP в лог — удобно дебажить
apply_php() {
  /usr/local/bin/php -r "$1" 2>&1 | while IFS= read -r line; do
    printf '%s [context-MGMT][php] %s\n' "$(date)" "$line" >> "$LOG_FILE"
  done
}

log "Starting Management Interface Context (version=${SCRIPT_VERSION}, IF=${MGMT_IF}, ENABLE=${MGMT_ENABLE}, PORT=${MGMT_PORT}, path=$(realpath "$0"))"

# Для инфы — активный путь к config.xml
CONF_PATH="$(/usr/local/bin/php -r "require_once(\"config.inc\"); global \$g; echo (\$g[\"conf_path\"] ?? \"/conf\");" 2>/dev/null)"
[ -z "$CONF_PATH" ] && CONF_PATH="/conf"
log "Detected conf path: ${CONF_PATH}/config.xml"

# -------------------------------------------------------------------
# Resolve pfSense logical IF (lan/wan/optX) -> real OS IF
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
# Helpers (PHP snippets)
# -------------------------------------------------------------------

# — Убедиться, что $config['aliases']['alias'] это массив, а не строка/пустота
php_ensure_aliases_array="
require_once(\"config.inc\");
global \$config;
if (!isset(\$config[\"aliases\"]) || !is_array(\$config[\"aliases\"])) { \$config[\"aliases\"] = []; }
if (!isset(\$config[\"aliases\"][\"alias\"]) || !is_array(\$config[\"aliases\"][\"alias\"])) { \$config[\"aliases\"][\"alias\"] = []; }
"

# — Финальная сборка: сперва алиасы, потом правила
php_apply_aliases_and_filter='
require_once("filter.inc");
if (function_exists("filter_generate_aliases_config")) {
  filter_generate_aliases_config();
}
filter_configure();
'

# -------------------------------------------------------------------
# MAIN LOGIC
# -------------------------------------------------------------------

if [ "$MGMT_ENABLE" = "YES" ]; then
  log "=== Enabling management interface $MGMT_IF ($REAL_IF) ==="

  # 1) Anti-lockout ON (ставим ключ — отключаем автоправило webGUI)
  log "Disabling webConfigurator anti-lockout rule (set noantilockout=yes)"
  apply_php "
    require_once('config.inc');
    global \$config;
    \$config['system']['webgui'] = \$config['system']['webgui'] ?? [];
    \$config['system']['webgui']['noantilockout'] = 'yes';
    write_config('[MGMT] Disable anti-lockout (set yes)');
  "

  # 2) Убираем gateway на MGMT_IF (исключаем из маршрутизации)
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

  # 3) Создаём/обновляем alias MGMT_PORTS (+ dirty), с защитой структуры
  log "Updating alias [MGMT_PORTS] with ports: ${MGMT_PORT}"
  apply_php "
    require_once('util.inc');
    ${php_ensure_aliases_array}
    global \$config;

    \$alias = 'MGMT_PORTS';
    \$ports = array_map('trim', explode(',', '${MGMT_PORT}'));

    // Удаляем старый MGMT_PORTS, если был
    \$config['aliases']['alias'] = array_values(array_filter(
      \$config['aliases']['alias'],
      function(\$a){ return !is_array(\$a) || (\$a['name'] ?? '') !== 'MGMT_PORTS'; }
    ));

    // Добавляем заново
    \$config['aliases']['alias'][] = [
      'name'=>\$alias,
      'type'=>'port',
      'address'=>implode(' ', \$ports),
      'descr'=>'[MGMT] Management Ports'
    ];

    write_config('[MGMT] Updated alias MGMT_PORTS');
    mark_subsystem_dirty('aliases');
  "

  # 4) Добавляем firewall-правила (очищаем старые [MGMT], добавляем новые)
  log "Adding [MGMT] firewall rules for $MGMT_IF"
  apply_php "
    require_once('config.inc');
    require_once('filter.inc');
    require_once('interfaces.inc');
    global \$config;
    \$if='${MGMT_IF}';
    \$ip=get_interface_ip(\$if) ?: '127.0.0.1';

    // Сносим старые [MGMT]-правила
    \$config['filter']['rule'] = array_values(array_filter(\$config['filter']['rule'] ?? [],
      function(\$r){ return !isset(\$r['descr']) || strpos(\$r['descr'],'[MGMT]')===false; }
    ));

    // Allow ICMP
    \$config['filter']['rule'][] = [
      'type'=>'pass','interface'=>\$if,'ipprotocol'=>'inet',
      'protocol'=>'icmp','source'=>['network'=>\$if],
      'destination'=>['address'=>\$ip],
      'descr'=>'[MGMT] Allow ICMP (ping)'
    ];
    // Allow TCP ports via alias
    \$config['filter']['rule'][] = [
      'type'=>'pass','interface'=>\$if,'ipprotocol'=>'inet',
      'protocol'=>'tcp','source'=>['network'=>\$if],
      'destination'=>['address'=>\$ip,'port'=>'MGMT_PORTS'],
      'descr'=>'[MGMT] Allow management ports (${MGMT_PORT})'
    ];
    // Block the rest
    \$config['filter']['rule'][] = [
      'type'=>'block','interface'=>\$if,'ipprotocol'=>'inet',
      'source'=>['network'=>\$if],
      'destination'=>['any'=>''],
      'descr'=>'[MGMT] Block all other traffic'
    ];

    write_config('[MGMT] Added management firewall rules');
  "

  # 5) Применяем: сперва генерим алиасы, потом фильтр
  log "Applying aliases + filter"
  apply_php "${php_apply_aliases_and_filter}"

  log "Management interface $MGMT_IF configured successfully"

else
  log "=== Disabling management interface $MGMT_IF ($REAL_IF) ==="

  # 1) Anti-lockout OFF (удаляем ключ — чтобы не запереться, делаем это первым)
  log "Re-enabling webConfigurator anti-lockout rule (remove noantilockout)"
  apply_php "
    require_once('config.inc');
    global \$config;
    if (isset(\$config['system']['webgui']['noantilockout'])) {
      unset(\$config['system']['webgui']['noantilockout']);
      write_config('[MGMT] Re-enable anti-lockout (remove key)');
    }
  "

  # 2) Сносим [MGMT] правила
  log "Removing [MGMT] firewall rules"
  apply_php "
    require_once('config.inc');
    require_once('filter.inc');
    global \$config;
    if (isset(\$config['filter']['rule'])) {
      \$config['filter']['rule'] = array_values(array_filter(\$config['filter']['rule'],
        function(\$r){ return !isset(\$r['descr']) || strpos(\$r['descr'],'[MGMT]')===false; }
      ));
      write_config('[MGMT] Removed management rules');
    }
  "

  # 3) Сносим алиас MGMT_PORTS (+ dirty), с защитой структуры
  log "Removing alias [MGMT_PORTS]"
  apply_php "
    require_once('config.inc');
    require_once('util.inc');
    global \$config;

    if (isset(\$config['aliases']) && !is_array(\$config['aliases'])) { \$config['aliases'] = []; }
    if (isset(\$config['aliases']['alias']) && is_array(\$config['aliases']['alias'])) {
      \$config['aliases']['alias'] = array_values(array_filter(
        \$config['aliases']['alias'],
        function(\$a){ return !is_array(\$a) || (\$a['name'] ?? '') !== 'MGMT_PORTS'; }
      ));
      write_config('[MGMT] Removed alias MGMT_PORTS');
      mark_subsystem_dirty('aliases');
    }
  "

  # 4) Убираем gateway на MGMT_IF
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

  # 5) Применяем: сперва алиасы, потом фильтр
  log "Applying aliases + filter"
  apply_php "${php_apply_aliases_and_filter}"

  log "Management interface $MGMT_IF disabled"
fi

log "Context script finished"
exit 0
