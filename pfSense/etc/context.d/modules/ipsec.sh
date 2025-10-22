#!/bin/sh
# -------------------------------------------------------------------
# pfSense IPsec Context Script (OpenNebula compatible)
# Author: shaman edition — v3.1 (2025-10-22)
# -------------------------------------------------------------------
# Context vars:
#   IPSEC_ENABLE=YES|NO
#   IPSEC_TUNNELS=N (1..N)
#   IPSEC1_PEER_IP, IPSEC1_PSK, IPSEC1_LOCAL_SUBNET, IPSEC1_REMOTE_SUBNET, IPSEC1_OUT_IF
#   IPSEC_CRYPTO_IKE=aes256 | sha256 | etc
#   IPSEC_HASH_IKE=sha256
#   IPSEC_DH_GROUP=14
#   IPSEC_CRYPTO_ESP=aes256
#   IPSEC_HASH_ESP=sha256
#   IPSEC_LIFETIME_IKE=86400
#   IPSEC_LIFETIME_ESP=28800
# -------------------------------------------------------------------

: "${IPSEC_ENABLE:=NO}"
: "${IPSEC_TUNNELS:=0}"
: "${IPSEC_CRYPTO_IKE:=aes256}"
: "${IPSEC_HASH_IKE:=sha256}"
: "${IPSEC_DH_GROUP:=14}"
: "${IPSEC_CRYPTO_ESP:=aes256}"
: "${IPSEC_HASH_ESP:=sha256}"
: "${IPSEC_LIFETIME_IKE:=86400}"
: "${IPSEC_LIFETIME_ESP:=28800}"

LOG_FILE="/var/log/context.log"
SCRIPT_VERSION="IPSEC v3.1 2025-10-22"

log() {
  printf '%s [context-IPSEC] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG_FILE"
}

apply_php() {
  /usr/local/bin/php -r "$1" 2>&1 | while IFS= read -r line; do
    printf '%s [context-IPSEC][php] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$line" >> "$LOG_FILE"
  done
}

log "Starting IPSEC Context (version=${SCRIPT_VERSION}, ENABLE=${IPSEC_ENABLE}, TUNNELS=${IPSEC_TUNNELS})"

# -------------------------------------------------------------------
# Skip if disabled
# -------------------------------------------------------------------
if [ "$IPSEC_ENABLE" != "YES" ]; then
  log "IPSEC disabled via context (IPSEC_ENABLE=${IPSEC_ENABLE})"
  exit 0
fi

PHPBIN="/usr/local/bin/php"
[ -x "$PHPBIN" ] || { log "Error: php CLI not found"; exit 1; }

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
# MAIN LOOP: build tunnels 1..N
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

    \$descr='${DESCR}';
    \$peer='${PEER_IP}';
    \$psk='${PSK}';
    \$lsub='${LSUB}';
    \$rsub='${RSUB}';
    \$iface='${IFACE}';

    // Remove existing ContextIPSEC_${idx} entries if any
    \$config['ipsec']['phase1'] = array_values(array_filter(\$config['ipsec']['phase1'], function(\$p){
      return !isset(\$p['descr']) || \$p['descr'] !== '${DESCR}';
    }));
    \$config['ipsec']['phase2'] = array_values(array_filter(\$config['ipsec']['phase2'], function(\$p){
      return !isset(\$p['descr']) || \$p['descr'] !== '${DESCR}';
    }));

    // Add Phase 1
    \$p1 = [
      'ikeid' => '${idx}',
      'interface' => \$iface,
      'remote-gateway' => (\$peer ?: 'any'),
      'p1mode' => 'main',
      'p1myidenttype' => 'myaddress',
      'p1peeridenttype' => 'address',
      'p1authentication_method' => 'pre_shared_key',
      'p1pskey' => \$psk,
      'p1exchange' => 'ikev2',
      'p1ealg' => '${IPSEC_CRYPTO_IKE}',
      'p1ealgkeylen' => '256',
      'p1hash' => '${IPSEC_HASH_IKE}',
      'p1dhgroup' => '${IPSEC_DH_GROUP}',
      'lifetime' => '${IPSEC_LIFETIME_IKE}',
      'descr' => '${DESCR}'
    ];
    \$config['ipsec']['phase1'][] = \$p1;

    // Add Phase 2
    \$p2 = [
      'ikeid' => '${idx}',
      'mode' => 'tunnel',
      'local-subnet' => \$lsub,
      'remote-subnet' => \$rsub,
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
    \$config['ipsec']['phase2'][] = \$p2;

    write_config('[Context-IPSEC] Added/updated tunnel ${DESCR}');
  "

  # -------------------------------------------------------------------
  # Firewall rules (WAN / IPsec)
  # -------------------------------------------------------------------
  log "Ensuring firewall rules for $IFACE (UDP 500/4500, ESP)"
  apply_php "
    require_once('config.inc');
    require_once('filter.inc');
    global \$config;
    \$if='${IFACE}';
    \$rules=\$config['filter']['rule'] ?? [];

    // Drop previous rules with same descr
    \$rules=array_values(array_filter(\$rules, function(\$r){
      return !isset(\$r['descr']) || strpos(\$r['descr'],'[Context-IPSEC-${idx}]')===false;
    }));

    \$rules[]=[
      'type'=>'pass','interface'=>\$if,'ipprotocol'=>'inet',
      'protocol'=>'udp','source'=>['any'=>''],'destination'=>['any'=>'','port'=>'500'],
      'descr'=>'[Context-IPSEC-${idx}] Allow IKE (UDP 500)'
    ];
    \$rules[]=[
      'type'=>'pass','interface'=>\$if,'ipprotocol'=>'inet',
      'protocol'=>'udp','source'=>['any'=>''],'destination'=>['any'=>'','port'=>'4500'],
      'descr'=>'[Context-IPSEC-${idx}] Allow NAT-T (UDP 4500)'
    ];
    \$rules[]=[
      'type'=>'pass','interface'=>\$if,'ipprotocol'=>'inet',
      'protocol'=>'esp','source'=>['any'=>''],'destination'=>['any'=>''],
      'descr'=>'[Context-IPSEC-${idx}] Allow ESP'
    ];

    \$config['filter']['rule'] = \$rules;
    write_config('[Context-IPSEC] Firewall rules for ${IFACE}');
    mark_subsystem_dirty('filter');
  "

  idx=$((idx + 1))
done

# -------------------------------------------------------------------
# Apply configuration (reload IPsec)
# -------------------------------------------------------------------
log "Applying IPsec and firewall configuration"
apply_php "${php_apply_reload}"

log "IPSEC Context applied successfully (Tunnels=${IPSEC_TUNNELS})"
exit 0
