#!/bin/sh
# -------------------------------------------------------------------
# pfSense IPsec Context Script (OpenNebula compatible)
# Author: shaman edition — v3.3 (2025-10-22)
# -------------------------------------------------------------------
# Context vars (test defaults for debugging)
# -------------------------------------------------------------------
: "${IPSEC_ENABLE:=YES}"
: "${IPSEC_TUNNELS:=1}"
: "${IPSEC1_PEER_IP:=188.130.234.215}"
: "${IPSEC1_PSK:=184ff2f58ac2766b41d1e39a6298ed65cd58f5b8b8868b623925}"
: "${IPSEC1_LOCAL_SUBNET:=LAN subnet}"
: "${IPSEC1_REMOTE_SUBNET:=192.168.201.0/24}"
: "${IPSEC1_OUT_IF:=wan}"
: "${IPSEC_CRYPTO_IKE:=aes256}"
: "${IPSEC_HASH_IKE:=sha256}"
: "${IPSEC_DH_GROUP:=14}"
: "${IPSEC_CRYPTO_ESP:=aes256}"
: "${IPSEC_HASH_ESP:=sha256}"
: "${IPSEC_LIFETIME_IKE:=86400}"
: "${IPSEC_LIFETIME_ESP:=28800}"

LOG_FILE="/var/log/context.log"
SCRIPT_VERSION="IPSEC v3.3 2025-10-22"
STATE_HASH_FILE="/var/run/context-ipsec.hash"

log() {
  printf '%s [context-IPSEC] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG_FILE"
}

apply_php() {
  /usr/local/bin/php -r "$1" 2>&1 | while IFS= read -r line; do
    printf '%s [context-IPSEC][php] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$line" >> "$LOG_FILE"
  done
}

sha256_q() {
  if command -v sha256 >/dev/null 2>&1; then sha256 -q
  else openssl dgst -sha256 -r | awk '{print $1}'
  fi
}

PHPBIN="/usr/local/bin/php"
[ -x "$PHPBIN" ] || { log "Error: php CLI not found"; exit 1; }

log "Starting IPSEC Context (version=${SCRIPT_VERSION}, ENABLE=${IPSEC_ENABLE}, TUNNELS=${IPSEC_TUNNELS})"

# -------------------------------------------------------------------
# Skip if disabled
# -------------------------------------------------------------------
if [ "$IPSEC_ENABLE" != "YES" ]; then
  log "IPSEC disabled via context"
  exit 0
fi

# -------------------------------------------------------------------
# Build signature of configuration (for change detection)
# -------------------------------------------------------------------
sig_base="${IPSEC_ENABLE}|${IPSEC_TUNNELS}|${IPSEC_CRYPTO_IKE}|${IPSEC_HASH_IKE}|${IPSEC_DH_GROUP}|${IPSEC_CRYPTO_ESP}|${IPSEC_HASH_ESP}|${IPSEC_LIFETIME_IKE}|${IPSEC_LIFETIME_ESP}"
for i in $(seq 1 "$IPSEC_TUNNELS"); do
  sig_base="${sig_base}|$(eval echo "\$IPSEC${i}_PEER_IP")|$(eval echo "\$IPSEC${i}_LOCAL_SUBNET")|$(eval echo "\$IPSEC${i}_REMOTE_SUBNET")|$(eval echo "\$IPSEC${i}_OUT_IF")|$(eval echo "\$IPSEC${i}_PSK")"
done
new_hash=$(printf "%s" "$sig_base" | sha256_q)

if [ -f "$STATE_HASH_FILE" ]; then
  old_hash=$(cat "$STATE_HASH_FILE")
  if [ "$new_hash" = "$old_hash" ]; then
    log "No changes in context variables, skipping execution"
    exit 0
  fi
fi
echo "$new_hash" > "$STATE_HASH_FILE"

# -------------------------------------------------------------------
# Prepare helper PHP snippets
# -------------------------------------------------------------------
php_prepare_arrays='
require_once("config.inc");
global $config;
if (!isset($config["ipsec"]) || !is_array($config["ipsec"])) $config["ipsec"] = [];
if (!isset($config["ipsec"]["phase1"]) || !is_array($config["ipsec"]["phase1"])) $config["ipsec"]["phase1"] = [];
if (!isset($config["ipsec"]["phase2"]) || !is_array($config["ipsec"]["phase2"])) $config["ipsec"]["phase2"] = [];
'

php_apply_reload='
require_once("ipsec.inc");
require_once("filter.inc");
log_error("[Context-IPSEC] Reloading IPsec and filter");
ipsec_configure();
filter_configure();
'

# -------------------------------------------------------------------
# Remove old ContextIPSEC_* if number reduced or missing
# -------------------------------------------------------------------
log "Checking for obsolete ContextIPSEC_* tunnels"
apply_php "
  require_once('config.inc');
  global \$config;
  ${php_prepare_arrays}
  \$current = range(1, ${IPSEC_TUNNELS});
  \$config['ipsec']['phase1'] = array_values(array_filter(\$config['ipsec']['phase1'], function(\$p) use(\$current){
    if (!isset(\$p['descr'])) return true;
    if (preg_match('/^ContextIPSEC_(\d+)/', \$p['descr'], \$m)) {
      return in_array((int)\$m[1], \$current);
    }
    return true;
  }));
  \$config['ipsec']['phase2'] = array_values(array_filter(\$config['ipsec']['phase2'], function(\$p) use(\$current){
    if (!isset(\$p['descr'])) return true;
    if (preg_match('/^ContextIPSEC_(\d+)/', \$p['descr'], \$m)) {
      return in_array((int)\$m[1], \$current);
    }
    return true;
  }));
  write_config('[Context-IPSEC] Cleanup obsolete ContextIPSEC_* entries');
"

# -------------------------------------------------------------------
# MAIN LOOP: create or update tunnels
# -------------------------------------------------------------------
idx=1
while [ "$idx" -le "$IPSEC_TUNNELS" ]; do
  DESCR="ContextIPSEC_${idx}"
  PEER_IP=$(eval echo "\$IPSEC${idx}_PEER_IP")
  PSK=$(eval echo "\$IPSEC${idx}_PSK")
  LSUB=$(eval echo "\$IPSEC${idx}_LOCAL_SUBNET")
  RSUB=$(eval echo "\$IPSEC${idx}_REMOTE_SUBNET")
  IFACE=$(eval echo "\$IPSEC${idx}_OUT_IF")
  [ -z "$IFACE" ] && IFACE="wan"

  log "Processing tunnel #${idx} ($DESCR) peer=${PEER_IP:-any} iface=$IFACE"

  apply_php "
    require_once('config.inc');
    require_once('ipsec.inc');
    global \$config;
    ${php_prepare_arrays}

    // remove same descr
    \$config['ipsec']['phase1'] = array_values(array_filter(\$config['ipsec']['phase1'], function(\$p){
      return !isset(\$p['descr']) || \$p['descr'] !== '${DESCR}';
    }));
    \$config['ipsec']['phase2'] = array_values(array_filter(\$config['ipsec']['phase2'], function(\$p){
      return !isset(\$p['descr']) || \$p['descr'] !== '${DESCR}';
    }));

    // phase1
    \$config['ipsec']['phase1'][] = [
      'ikeid' => '${idx}',
      'interface' => '${IFACE}',
      'remote-gateway' => '${PEER_IP}',
      'p1authentication_method' => 'pre_shared_key',
      'p1pskey' => '${PSK}',
      'p1exchange' => 'ikev2',
      'p1ealg' => '${IPSEC_CRYPTO_IKE}',
      'p1ealgkeylen' => '256',
      'p1hash' => '${IPSEC_HASH_IKE}',
      'p1dhgroup' => '${IPSEC_DH_GROUP}',
      'lifetime' => '${IPSEC_LIFETIME_IKE}',
      'descr' => '${DESCR}'
    ];

    // phase2
    \$config['ipsec']['phase2'][] = [
      'ikeid' => '${idx}',
      'mode' => 'tunnel',
      'local-subnet' => '${LSUB}',
      'remote-subnet' => '${RSUB}',
      'protocol' => 'esp',
      'encryption-algorithm-option' => [
        'name' => '${IPSEC_CRYPTO_ESP}',
        'keylen' => '256'
      ],
      'hash-algorithm-option' => '${IPSEC_HASH_ESP}',
      'pfsgroup' => '${IPSEC_DH_GROUP}',
      'lifetime' => '${IPSEC_LIFETIME_ESP}',
      'descr' => '${DESCR}'
    ];

    write_config('[Context-IPSEC] Added/updated ${DESCR}');
  "

  # --- firewall ---
  log "Ensuring firewall rules for $IFACE (UDP 500/4500, ESP)"
  apply_php "
    require_once('config.inc');
    require_once('filter.inc');
    global \$config;
    \$if='${IFACE}';
    \$rules=\$config['filter']['rule'] ?? [];
    \$rules=array_values(array_filter(\$rules, function(\$r){
      return !isset(\$r['descr']) || strpos(\$r['descr'],'[Context-IPSEC-${idx}]')===false;
    }));
    \$rules[]=['type'=>'pass','interface'=>\$if,'ipprotocol'=>'inet','protocol'=>'udp',
      'destination'=>['any'=>'','port'=>'500'],'descr'=>'[Context-IPSEC-${idx}] Allow IKE (UDP 500)'];
    \$rules[]=['type'=>'pass','interface'=>\$if,'ipprotocol'=>'inet','protocol'=>'udp',
      'destination'=>['any'=>'','port'=>'4500'],'descr'=>'[Context-IPSEC-${idx}] Allow NAT-T (UDP 4500)'];
    \$rules[]=['type'=>'pass','interface'=>\$if,'ipprotocol'=>'inet','protocol'=>'esp',
      'destination'=>['any'=>''],'descr'=>'[Context-IPSEC-${idx}] Allow ESP'];
    \$config['filter']['rule'] = \$rules;
    write_config('[Context-IPSEC] Firewall rules for ${IFACE}');
    mark_subsystem_dirty('filter');
  "

  idx=$((idx + 1))
done

# -------------------------------------------------------------------
# Apply configuration
# -------------------------------------------------------------------
log "Reloading IPsec and firewall"
apply_php "${php_apply_reload}"

log "IPSEC Context applied successfully (Tunnels=${IPSEC_TUNNELS})"
exit 0
