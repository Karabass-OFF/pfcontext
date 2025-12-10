# shellcheck shell=sh disable=SC2034
# ============================================================
# 🚀 Force immediate IPsec initiation — non-blocking
# ============================================================
log "🚀 Forcing immediate IPsec initiation (non-blocking)"

SWANCTL_CONF="/var/etc/ipsec/swanctl.conf"

# 1) Wait up to 10s for an IPv4 address to appear on the WAN (for rules/IDs)
WAN_IP=""
for i in 1 2 3 4 5 6 7 8 9 10; do
  WAN_IP=$(/usr/local/bin/php -r 'require_once("/etc/inc/interfaces.inc"); echo get_interface_ip("wan") ?: "";' 2>/dev/null || true)
  [ -n "$WAN_IP" ] && break
  sleep 1
done
#[ -n "$WAN_IP" ] && log "  WAN IPv4: ${WAN_IP}" || log "  WARNING: WAN IPv4 empty"
[ -n "$WAN_IP" ] && log "WAN IPv4: ${WAN_IP}" || true
[ -z "$WAN_IP" ] && log "WARNING: WAN IPv4 empty"

# 2) Ensure VICI is present; if not — quick restart of the starter
[ -S /var/run/charon.vici ] || { /usr/local/sbin/ipsec stop >/dev/null 2>&1 || true; sleep 1; /usr/local/sbin/ipsec start >/dev/null 2>&1 || true; sleep 1; }

# 3) Explicitly load swanctl.conf (valid flags for 5.9.14)
 /usr/local/sbin/swanctl --load-creds --clear --file "$SWANCTL_CONF" >/dev/null 2>&1 || true
 /usr/local/sbin/swanctl --load-conns             --file "$SWANCTL_CONF" >/dev/null 2>&1 || true

# 4) List of conns from VICI; if empty — use ikeid from config.xml
names=$(/usr/local/sbin/swanctl --list-conns 2>/dev/null | awk -F: '/^[A-Za-z0-9._-]+:/{print $1}' | grep -v '^bypass$' | sort -Vu)
if [ -z "$names" ]; then
  names="$(
    # shellcheck disable=SC2016
    /usr/local/bin/php -r 'require_once("/etc/inc/config.inc"); foreach (($config["ipsec"]["phase1"] ?? []) as $p1) if (!empty($p1["ikeid"])) echo "con".$p1["ikeid"], "\n";' 2>/dev/null \
    | sort -Vu
  )"
  log "  VICI empty, fallback names: $(printf '%s' "$names")"
fi
# 5) Asynchronous initiation (fire-and-forget), without waiting for the peer’s response
initiate_async() {
  c="$1"
  if /usr/local/sbin/swanctl --list-conns 2>/dev/null | awk -F: '/^[A-Za-z0-9._-]+:/{print $1}' | grep -qx "$c"; then
    # If the child is seen as a tunnel — trigger the CHILD; otherwise trigger the IKE; all in the background
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

# 6) Non-blocking “polling” for up to 8s purely for logging (not required to find an SA)
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

# 6.1) Check: if there is no CHILD SA, initiate it manually (emergency kick)
if ! /usr/local/sbin/swanctl --list-sas 2>/dev/null | grep -q 'INSTALLED'; then
  log "⚠️  No CHILD_SA detected after initial wait — forcing manual initiation"
  for c in $names; do
    [ "$c" = "bypass" ] && continue
    nohup /usr/local/sbin/swanctl --initiate --child "$c" >/dev/null 2>&1 &
    log "  🔁 forced reinitiate CHILD $c"
  done
  sleep 3
fi
log "✅ Completed successfully (non-blocking initiate)"