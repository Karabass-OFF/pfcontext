# shellcheck shell=sh disable=SC2034
# ============================================================
# 🚀 Force immediate IPsec initiation — non-blocking
# ============================================================
log "🚀 Forcing immediate IPsec initiation (non-blocking)"

SWANCTL_CONF="/var/etc/ipsec/swanctl.conf"

# 1) Ждём до 10с, пока появится IPv4 на WAN (для правил/ID)
WAN_IP=""
for i in 1 2 3 4 5 6 7 8 9 10; do
  WAN_IP=$(/usr/local/bin/php -r 'require_once("/etc/inc/interfaces.inc"); echo get_interface_ip("wan") ?: "";' 2>/dev/null || true)
  [ -n "$WAN_IP" ] && break
  sleep 1
done
#[ -n "$WAN_IP" ] && log "  WAN IPv4: ${WAN_IP}" || log "  WARNING: WAN IPv4 empty"
[ -n "$WAN_IP" ] && log "WAN IPv4: ${WAN_IP}" || true
[ -z "$WAN_IP" ] && log "WARNING: WAN IPv4 empty"

# 2) Убедиться, что VICI есть; если нет — быстрый рестарт стартера
[ -S /var/run/charon.vici ] || { /usr/local/sbin/ipsec stop >/dev/null 2>&1 || true; sleep 1; /usr/local/sbin/ipsec start >/dev/null 2>&1 || true; sleep 1; }

# 3) Явно загрузить swanctl.conf (валидные флаги для 5.9.14)
 /usr/local/sbin/swanctl --load-creds --clear --file "$SWANCTL_CONF" >/dev/null 2>&1 || true
 /usr/local/sbin/swanctl --load-conns             --file "$SWANCTL_CONF" >/dev/null 2>&1 || true

# 4) Список conn-ов из VICI; если пусто — по ikeid из config.xml
names=$(/usr/local/sbin/swanctl --list-conns 2>/dev/null | awk -F: '/^[A-Za-z0-9._-]+:/{print $1}' | grep -v '^bypass$' | sort -Vu)
if [ -z "$names" ]; then
  names="$(
    # shellcheck disable=SC2016
    /usr/local/bin/php -r 'require_once("/etc/inc/config.inc"); foreach (($config["ipsec"]["phase1"] ?? []) as $p1) if (!empty($p1["ikeid"])) echo "con".$p1["ikeid"], "\n";' 2>/dev/null \
    | sort -Vu
  )"
  log "  VICI empty, fallback names: $(printf '%s' "$names")"
fi

# 5) Асинхронное инициирование (fire-and-forget), без ожидания ответа peer
initiate_async() {
  c="$1"
  if /usr/local/sbin/swanctl --list-conns 2>/dev/null | awk -F: '/^[A-Za-z0-9._-]+:/{print $1}' | grep -qx "$c"; then
    # если child виден как туннель — дергаем CHILD, иначе IKE; всё в фоне
    if /usr/local/sbin/swanctl --list-conns 2>/dev/null | awk '/^[A-Za-z0-9._-]+: TUNNEL/{ sub(":", "", $1); print $1 }' | grep -qx "$c"; then
      nohup /usr/local/sbin/swanctl --initiate --child "$c" >/dev/null 2>&1 &
      log "  initiate CHILD $c (async)"
    else
      nohup /usr/local/sbin/swanctl --initiate --ike "$c"   >/dev/null 2>&1 &
      log "  initiate IKE   $c (async)"
    fi
  fi
}

if [ -n "$names" ]; then
  for c in $names; do
    [ "$c" = "bypass" ] && continue
    initiate_async "$c"
  done
else
  log "  ERROR: no connection names to initiate"
fi

# 6) Неблокирующий «пуллинг» до 8с чисто для логов (не обязан находить SA)
deadline=$(( $(date +%s) + 8 ))
while [ "$(date +%s)" -lt $deadline ]; do
  if /usr/local/sbin/swanctl --list-sas 2>/dev/null | grep -q '^con'; then
    break
  fi
  sleep 1
done

/usr/local/sbin/swanctl --list-sas 2>/dev/null \
  | /usr/bin/awk '{print strftime(), " [context-IPSEC][sas] ", $0}' >> "$LOG_FILE" || true

#/usr/bin/tail -n 200 /var/log/ipsec.log 2>/dev/null \
#  | /usr/bin/awk -v ts="$(date '+%Y-%m-%dT%H:%M:%S%z')" '{printf "%s [context-IPSEC][ipsec.log] %s\n", ts, $0}' \
#  >> "$LOG_FILE" || true

log "✅ Completed successfully (non-blocking initiate)"