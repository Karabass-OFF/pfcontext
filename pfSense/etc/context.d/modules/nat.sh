#!/bin/sh
# =====================================================================
#  pfContext Module — NAT (Outbound)
#  Версия: v1.1
#  Назначение: автоматическое создание outbound NAT для внутренних сетей
# =====================================================================

# Переменные context:
#   NAT_ENABLE=YES|NO
#   NAT_IF=wan                       # внешний интерфейс
#   NAT_MODE=automatic|hybrid|advanced|disabled
#   NAT_SRC="192.168.10.0/24 192.168.20.0/24"  # сети, для которых делаем NAT
#
# Рекомендуемый вариант:
#   NAT_ENABLE=YES
#   NAT_IF=wan
#   NAT_MODE=hybrid
#   NAT_SRC="192.168.201.0/24"       # ТОЛЬКО локальные сети, НЕ 0.0.0.0/0

: "${NAT_ENABLE:=NO}"
: "${NAT_IF:=wan}"
: "${NAT_MODE:=hybrid}"
: "${NAT_SRC:=}"

LOG="/var/log/context.log"

log() {
  printf '%s [context-NAT:nat.sh] %s\n' "$(date)" "$*" >> "$LOG"
}

nat_apply() {
  log "Старт применения NAT-модуля"

  if [ "$NAT_ENABLE" != "YES" ]; then
    log "NAT отключён (NAT_ENABLE=$NAT_ENABLE) — выходим"
    return 0
  fi

  # Проверяем, что интерфейс существует
  IF_REAL=$(/usr/local/bin/php -r "
    require_once('/etc/inc/interfaces.inc');
    \$if = get_real_interface('$NAT_IF');
    if (!empty(\$if)) echo \$if;
  " 2>/dev/null)

  if [ -z "$IF_REAL" ]; then
    log "ОШИБКА: интерфейс '$NAT_IF' не существует (get_real_interface вернул пусто)"
    return 1
  fi

  log "Используем внешний интерфейс: $NAT_IF ($IF_REAL)"
  log "Запрошенный режим NAT: $NAT_MODE"
  [ -n "$NAT_SRC" ] && log "Сети для NAT: $NAT_SRC" || log "NAT_SRC пустой — кастомных правил не будет"

  # ----------------------------------------------------------
  # 1) Устанавливаем режим outbound NAT и при необходимости
  #    пересобираем список правил
  # ----------------------------------------------------------
  /usr/local/bin/php -r "
    require_once('/etc/inc/config.inc');
    require_once('/etc/inc/filter.inc');
    global \$config;

    \$nat_if   = '$NAT_IF';
    \$nat_mode = '$NAT_MODE';
    \$nat_src  = '$NAT_SRC';

    if (!is_array(\$config['nat']))           \$config['nat'] = [];
    if (!is_array(\$config['nat']['outbound'])) \$config['nat']['outbound'] = [];

    // допустимые значения: automatic, hybrid, advanced, disabled
    \$config['nat']['outbound']['mode'] = \$nat_mode;

    // Если режим hybrid или advanced — управляем правилами сами
    if (\$nat_mode === 'hybrid' || \$nat_mode === 'advanced') {
        // очищаем прежние правила (идемпотентность)
        \$config['nat']['outbound']['rule'] = [];

        \$nat_src = trim(\$nat_src);
        if (\$nat_src !== '') {
            foreach (preg_split('/\s+/', \$nat_src) as \$net) {
                if (\$net === '') continue;
                \$config['nat']['outbound']['rule'][] = [
                    'interface'     => \$nat_if,
                    'source'        => ['network' => \$net],
                    'destination'   => ['any' => ''],
                    'protocol'      => 'any',
                    'natport'       => '',
                    'target'        => '',
                    'poolopts'      => 'round-robin',
                    'staticnatport' => 'auto',
                ];
            }
        }
    }

    write_config('context: outbound NAT updated');

    // применяем firewall/NAT
    filter_configure();
  " 2>>"$LOG"

  # ----------------------------------------------------------
  # 2) Логируем текущий режим и количество правил для контроля
  # ----------------------------------------------------------
  /usr/local/bin/php -r "
    require_once('/etc/inc/config.inc');
    global \$config;
    \$mode = \$config['nat']['outbound']['mode'] ?? 'undefined';
    \$count = 0;
    if (isset(\$config['nat']['outbound']['rule']) && is_array(\$config['nat']['outbound']['rule'])) {
        \$count = count(\$config['nat']['outbound']['rule']);
    }
     echo '[' . date('Y-m-d H:i:s') . '][context-NAT:nat.sh] Итоговый режим: ' . \$mode . ', правил: ' . \$count . \"\n\";
  " >>"$LOG" 2>/dev/null

  log "NAT модуль завершён"
}

nat_apply
