#!/bin/sh
# ============================================================
# pfSense Context Module: IPSEC
# Version: 0.4.4-arrayfix
# Author: ContextOnly
# Compatible with pfSense 2.7 / 2.8
# Purpose: Idempotent IPsec configuration from Context vars
# ============================================================

set -eu
LOG="/var/log/context.log"
PHP="/usr/local/bin/php"

# ------------------------------------------------------------
# 🔧 DEFAULTS for debug / fallback
# ------------------------------------------------------------
: "${CONTEXT_IPSEC_ENABLE:=YES}"
: "${CONTEXT_IPSEC_TUNNELS:=1}"

: "${CONTEXT_IPSEC_1_REMOTE:=192.0.2.1}"
: "${CONTEXT_IPSEC_1_PSK:=debugsecret}"
: "${CONTEXT_IPSEC_1_LOCALID:=wan}"
: "${CONTEXT_IPSEC_1_REMOTEID:=192.0.2.1}"
: "${CONTEXT_IPSEC_1_PHASE1_ENC:=aes256}"
: "${CONTEXT_IPSEC_1_PHASE1_HASH:=sha256}"
: "${CONTEXT_IPSEC_1_PHASE1_DH:=14}"
: "${CONTEXT_IPSEC_1_PHASE2_PROTO:=esp}"
: "${CONTEXT_IPSEC_1_PHASE2_ENC:=aes256}"
: "${CONTEXT_IPSEC_1_PHASE2_HASH:=sha256}"
: "${CONTEXT_IPSEC_1_PHASE2_PFS:=off}"
: "${CONTEXT_IPSEC_1_LOCAL_NET:=10.10.0.0/24}"
: "${CONTEXT_IPSEC_1_REMOTE_NET:=10.20.0.0/24}"

# ------------------------------------------------------------
# ✅ CHECK ENABLE
# ------------------------------------------------------------
if [ "$CONTEXT_IPSEC_ENABLE" != "YES" ]; then
  echo "$(date) [context-IPSEC] Disabled via CONTEXT_IPSEC_ENABLE" >> "$LOG"
  exit 0
fi

TUNNELS="$CONTEXT_IPSEC_TUNNELS"
if [ "$TUNNELS" -eq 0 ]; then
  echo "$(date) [context-IPSEC] No tunnels defined" >> "$LOG"
  exit 0
fi

<<<<<<< HEAD
# Самовосстановление структуры конфигурации IPsec и безопасный подсчет Phase1
P1_COUNT=$($PHP -r '
require_once("/etc/inc/config.inc");
$changed = false;
if (!isset($config["ipsec"]) || !is_array($config["ipsec"])) { $config["ipsec"] = []; $changed = true; }
if (!isset($config["ipsec"]["phase1"]) || !is_array($config["ipsec"]["phase1"])) { $config["ipsec"]["phase1"] = []; $changed = true; }
if (!isset($config["ipsec"]["phase2"]) || !is_array($config["ipsec"]["phase2"])) { $config["ipsec"]["phase2"] = []; $changed = true; }
if ($changed) { write_config("Normalize IPsec arrays via context selfheal"); }
echo (string)count($config["ipsec"]["phase1"]);
')
echo "$(date) [context-IPSEC] Current phase1 entries: $P1_COUNT" >> "$LOG"
=======
# ------------------------------------------------------------
# 🔍 Enumerate current IPsec config
# ------------------------------------------------------------
CURRENT_IPSEC=$($PHP -r '
require_once("/etc/inc/config.inc");
echo isset($config["ipsec"]["phase1"]) ? count($config["ipsec"]["phase1"]) : 0;
')
echo "$(date) [context-IPSEC] Current phase1 entries: $CURRENT_IPSEC" >> "$LOG"
>>>>>>> 083cdd0 (WIP: temporary changes)

# ------------------------------------------------------------
# 🔁 PROCESS EACH TUNNEL (accumulate changes)
# ------------------------------------------------------------
CHANGED=0
i=1
while [ "$i" -le "$TUNNELS" ]; do
  eval REMOTE=\$CONTEXT_IPSEC_${i}_REMOTE
  eval PSK=\$CONTEXT_IPSEC_${i}_PSK
  eval LOCALID=\$CONTEXT_IPSEC_${i}_LOCALID
  eval REMOTEID=\$CONTEXT_IPSEC_${i}_REMOTEID
  eval LOCAL_NET=\$CONTEXT_IPSEC_${i}_LOCAL_NET
  eval REMOTE_NET=\$CONTEXT_IPSEC_${i}_REMOTE_NET
  eval P1_ENC=\$CONTEXT_IPSEC_${i}_PHASE1_ENC
  eval P1_HASH=\$CONTEXT_IPSEC_${i}_PHASE1_HASH
  eval P1_DH=\$CONTEXT_IPSEC_${i}_PHASE1_DH
  eval P2_PROTO=\$CONTEXT_IPSEC_${i}_PHASE2_PROTO
  eval P2_ENC=\$CONTEXT_IPSEC_${i}_PHASE2_ENC
  eval P2_HASH=\$CONTEXT_IPSEC_${i}_PHASE2_HASH
  eval P2_PFS=\$CONTEXT_IPSEC_${i}_PHASE2_PFS

  echo "$(date) [context-IPSEC] → Processing tunnel #$i ($LOCALID → $REMOTE)" >> "$LOG"

  EXIST=$($PHP -r "
require_once('/etc/inc/config.inc');
\$found = false;
<<<<<<< HEAD
// Normalize to arrays to avoid PHP 8 type errors
if (!isset(\$config['ipsec']) || !is_array(\$config['ipsec'])) { \$config['ipsec'] = []; }
if (!isset(\$config['ipsec']['phase1']) || !is_array(\$config['ipsec']['phase1'])) { \$config['ipsec']['phase1'] = []; }
foreach (\$config['ipsec']['phase1'] as \$p1) {
  if (isset(\$p1['remote-gateway']) && \$p1['remote-gateway'] == '$REMOTE') { \$found = true; break; }
=======
if (isset(\$config['ipsec']['phase1'])) {
  foreach ((array)\$config['ipsec']['phase1'] as \$p1) {
    if (isset(\$p1['remote-gateway']) && \$p1['remote-gateway'] === '$REMOTE') { \$found = true; break; }
  }
>>>>>>> 083cdd0 (WIP: temporary changes)
}
echo \$found ? 'YES' : 'NO';
")

<<<<<<< HEAD
  if [ "$EXIST" = "NO" ]; then
    echo "$(date) [context-IPSEC] Creating new tunnel to $REMOTE" >> "$LOG"
    LOCALID="$LOCALID" REMOTE="$REMOTE" PSK="$PSK" LOCAL_NET="$LOCAL_NET" REMOTE_NET="$REMOTE_NET" $PHP <<'EOF'
<?php
require_once("/etc/inc/config.inc");
require_once("/etc/inc/ipsec.inc");
// Normalize IPsec config structures for PHP 8 strictness
\$config['ipsec'] = (isset(\$config['ipsec']) && is_array(\$config['ipsec'])) ? \$config['ipsec'] : [];
if (!isset(\$config['ipsec']['phase1']) || !is_array(\$config['ipsec']['phase1'])) { \$config['ipsec']['phase1'] = []; }
if (!isset(\$config['ipsec']['phase2']) || !is_array(\$config['ipsec']['phase2'])) { \$config['ipsec']['phase2'] = []; }
\$p1 = [
  'ikeid' => uniqid(),
  'disabled' => 'no',
  'interface' => getenv('LOCALID'),
  'remote-gateway' => getenv('REMOTE'),
  'pre-shared-key' => getenv('PSK'),
  'proposal' => 'aes256-sha256',
  'dhgroup' => '2',
  'lifetime' => '28800',
=======
  if [ "$EXIST" = "YES" ]; then
    echo "$(date) [context-IPSEC]   Tunnel to $REMOTE already exists — skipping create" >> "$LOG"
  else
    echo "$(date) [context-IPSEC]   Creating new tunnel to $REMOTE" >> "$LOG"

    REMOTE="$REMOTE" PSK="$PSK" LOCALID="$LOCALID" LOCAL_NET="$LOCAL_NET" REMOTE_NET="$REMOTE_NET" \
    P1_ENC="$P1_ENC" P1_HASH="$P1_HASH" P1_DH="$P1_DH" \
    P2_PROTO="$P2_PROTO" P2_ENC="$P2_ENC" P2_HASH="$P2_HASH" P2_PFS="$P2_PFS" \
    $PHP <<'EOF' && CHANGED=1 || true
<?php
require_once("/etc/inc/config.inc");
require_once("/etc/inc/ipsec.inc");

# --- Defensive fix: always ensure arrays ---
if (!isset($config['ipsec']) || !is_array($config['ipsec'])) $config['ipsec'] = [];
foreach (['phase1','phase2','pre-shared-key'] as $k) {
    if (!isset($config['ipsec'][$k]) || !is_array($config['ipsec'][$k])) {
        unset($config['ipsec'][$k]); # remove broken string nodes
        $config['ipsec'][$k] = [];
    }
}

$ikeid = uniqid();
$p1 = [
  'ikeid'           => $ikeid,
  'disabled'        => 'no',
  'interface'       => getenv('LOCALID'),
  'remote-gateway'  => getenv('REMOTE'),
  'pre-shared-key'  => getenv('PSK'),
  'proposal'        => getenv('P1_ENC') . '-' . getenv('P1_HASH'),
  'dhgroup'         => getenv('P1_DH'),
  'lifetime'        => '28800',
>>>>>>> 083cdd0 (WIP: temporary changes)
];

$p2 = [
  'ikeid'                      => $ikeid,
  'reqid'                      => uniqid(),
  'mode'                       => 'tunnel',
  'protocol'                   => getenv('P2_PROTO') ?: 'esp',
  'encryption-algorithm-option'=> [ getenv('P2_ENC') ?: 'aes256' ],
  'hash-algorithm-option'      => [ getenv('P2_HASH') ?: 'sha256' ],
  'pfsgroup'                   => getenv('P2_PFS') ?: 'off',
  'lifetime'                   => '3600',
  'localid'                    => ['type'=>'network','address'=>getenv('LOCAL_NET')],
  'remoteid'                   => ['type'=>'network','address'=>getenv('REMOTE_NET')],
];

$config['ipsec']['phase1'][] = $p1;
$config['ipsec']['phase2'][] = $p2;

write_config('Context: add IPsec tunnel (arrayfix)');
echo "OK";
EOF
  fi

  i=$((i + 1))
done

# ------------------------------------------------------------
# 🔄 Apply only if changed
# ------------------------------------------------------------
if [ "$CHANGED" -eq 1 ]; then
  echo "$(date) [context-IPSEC] Applying IPsec config (ipsec_configure)" >> "$LOG"
  $PHP -r "require_once('/etc/inc/config.inc'); require_once('/etc/inc/ipsec.inc'); ipsec_configure();"
  if [ -x /usr/local/sbin/swanctl ]; then
    /usr/local/sbin/swanctl --load-creds >/dev/null 2>&1 || true
  fi
else
  echo "$(date) [context-IPSEC] No changes detected — nothing to apply" >> "$LOG"
fi

echo "$(date) [context-IPSEC] ✅ Completed (Tunnels=$TUNNELS, Changed=$CHANGED)" >> "$LOG"
exit 0
