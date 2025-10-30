#!/bin/sh
# pfSense Context Module: IPSEC

LOG="/var/log/context.log"
PHP="/usr/local/bin/php"
CONFIGCTL="/usr/local/sbin/configctl"

echo "$(date) [context-IPSEC] Starting IPSEC Context" >> "$LOG"

# Проверяем, нужно ли включать
if [ "${CONTEXT_IPSEC_ENABLE:-NO}" != "YES" ]; then
  echo "$(date) [context-IPSEC] Disabled via CONTEXT_IPSEC_ENABLE" >> "$LOG"
  exit 0
fi

TUNNELS=${CONTEXT_IPSEC_TUNNELS:-0}
if [ "$TUNNELS" -eq 0 ]; then
  echo "$(date) [context-IPSEC] No tunnels defined" >> "$LOG"
  exit 0
fi

# Проверим текущие IPsec туннели (JSON)
CURRENT_IPSEC=$($PHP -r '
require_once("/etc/inc/ipsec.inc");
require_once("/etc/inc/config.inc");
echo json_encode($config["ipsec"]["phase1"]);
')

# Счётчик туннелей
i=1
while [ "$i" -le "$TUNNELS" ]; do
  eval REMOTE=\$CONTEXT_IPSEC_${i}_REMOTE
  eval PSK=\$CONTEXT_IPSEC_${i}_PSK
  eval LOCALID=\$CONTEXT_IPSEC_${i}_LOCALID
  eval REMOTEID=\$CONTEXT_IPSEC_${i}_REMOTEID
  eval LOCAL_NET=\$CONTEXT_IPSEC_${i}_LOCAL_NET
  eval REMOTE_NET=\$CONTEXT_IPSEC_${i}_REMOTE_NET

  echo "$(date) [context-IPSEC] Processing tunnel #$i to $REMOTE" >> "$LOG"

  # Проверяем, существует ли уже туннель
  EXIST=$($PHP -r "
require_once('/etc/inc/config.inc');
\$found = false;
// Normalize to arrays to avoid PHP 8 type errors
if (!isset(\$config['ipsec']) || !is_array(\$config['ipsec'])) { \$config['ipsec'] = []; }
if (!isset(\$config['ipsec']['phase1']) || !is_array(\$config['ipsec']['phase1'])) { \$config['ipsec']['phase1'] = []; }
foreach (\$config['ipsec']['phase1'] as \$p1) {
  if (isset(\$p1['remote-gateway']) && \$p1['remote-gateway'] == '$REMOTE') { \$found = true; break; }
}
echo \$found ? 'YES' : 'NO';
")

  if [ "$EXIST" = "NO" ]; then
    echo "$(date) [context-IPSEC] Creating new tunnel to $REMOTE" >> "$LOG"
    $PHP <<'EOF'
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
];
\$p2 = [
  'reqid' => uniqid(),
  'mode' => 'tunnel',
  'protocol' => 'esp',
  'encryption-algorithm-option' => ['aes256'],
  'hash-algorithm-option' => ['sha256'],
  'pfsgroup' => 'off',
  'localid' => ['type' => 'network', 'address' => getenv('LOCAL_NET')],
  'remoteid' => ['type' => 'network', 'address' => getenv('REMOTE_NET')],
];
\$config['ipsec']['phase1'][] = \$p1;
\$config['ipsec']['phase2'][] = \$p2;
write_config('Added IPsec tunnel via context');
ipsec_configure();
?>
EOF
  else
    echo "$(date) [context-IPSEC] Tunnel to $REMOTE already exists — skipping" >> "$LOG"
  fi

  i=$((i + 1))
done

# Применяем изменения
$CONFIGCTL ipsec reload

echo "$(date) [context-IPSEC] Completed successfully (Tunnels=$TUNNELS)" >> "$LOG"
exit 0
