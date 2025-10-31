#!/bin/sh
set -eu

# ============================================================
# 🔧 DEFAULTS (для отладки без контекста ISO)
# ============================================================

: "${CONTEXT_IPSEC_ENABLE:=YES}"
: "${CONTEXT_IPSEC_TUNNELS:=3}"

# --- Phase1 (IKE) ---
: "${IPSEC_P1_IKE:=ikev2}"
: "${IPSEC_P1_ENC_NAME:=aes}"
: "${IPSEC_P1_ENC_KEYLEN:=256}"
: "${IPSEC_P1_HASH:=sha256}"
: "${IPSEC_P1_DH:=14}"
: "${IPSEC_P1_LIFETIME:=86400}"

# --- Phase2 (ESP) ---
: "${IPSEC_P2_PROTO:=esp}"
: "${IPSEC_P2_ENC_NAME:=aes}"
: "${IPSEC_P2_ENC_KEYLEN:=256}"
: "${IPSEC_P2_AUTH:=sha256}"
: "${IPSEC_P2_PFS:=14}"
: "${IPSEC_P2_LIFETIME:=28800}"

# ============================================================
# 🔁 Применяем дефолты ко всем туннелям
# ============================================================

for i in $(seq 1 "$CONTEXT_IPSEC_TUNNELS"); do
  # Phase1
  eval ": \"\${CONTEXT_IPSEC_${i}_P1_IKE:=${IPSEC_P1_IKE}}\""
  eval ": \"\${CONTEXT_IPSEC_${i}_P1_ENC_NAME:=${IPSEC_P1_ENC_NAME}}\""
  eval ": \"\${CONTEXT_IPSEC_${i}_P1_ENC_KEYLEN:=${IPSEC_P1_ENC_KEYLEN}}\""
  eval ": \"\${CONTEXT_IPSEC_${i}_P1_HASH:=${IPSEC_P1_HASH}}\""
  eval ": \"\${CONTEXT_IPSEC_${i}_P1_DH:=${IPSEC_P1_DH}}\""
  eval ": \"\${CONTEXT_IPSEC_${i}_P1_LIFETIME:=${IPSEC_P1_LIFETIME}}\""

  # Phase2
  eval ": \"\${CONTEXT_IPSEC_${i}_P2_PROTO:=${IPSEC_P2_PROTO}}\""
  eval ": \"\${CONTEXT_IPSEC_${i}_P2_ENC_NAME:=${IPSEC_P2_ENC_NAME}}\""
  eval ": \"\${CONTEXT_IPSEC_${i}_P2_ENC_KEYLEN:=${IPSEC_P2_ENC_KEYLEN}}\""
  eval ": \"\${CONTEXT_IPSEC_${i}_P2_AUTH:=${IPSEC_P2_AUTH}}\""
  eval ": \"\${CONTEXT_IPSEC_${i}_P2_PFS:=${IPSEC_P2_PFS}}\""
  eval ": \"\${CONTEXT_IPSEC_${i}_P2_LIFETIME:=${IPSEC_P2_LIFETIME}}\""
done

# ============================================================
# 🧠 Пример конкретных туннелей (меняются только уникальные)
# ============================================================

: "${CONTEXT_IPSEC_1_REMOTE:=91.185.11.170}"
: "${CONTEXT_IPSEC_1_PSK:=e64f13bbab157151d8555bde068a0350dc84737efc7df32f6f822909}"
: "${CONTEXT_IPSEC_1_LOCALID:=wan}"
: "${CONTEXT_IPSEC_1_LOCAL_NET:=192.168.201.0/24}"
: "${CONTEXT_IPSEC_1_REMOTE_NET:=10.11.11.0/24}"

: "${CONTEXT_IPSEC_2_REMOTE:=203.0.113.20}"
: "${CONTEXT_IPSEC_2_PSK:=SecretB}"
: "${CONTEXT_IPSEC_2_LOCALID:=wan}"
: "${CONTEXT_IPSEC_2_LOCAL_NET:=10.10.0.0/24}"
: "${CONTEXT_IPSEC_2_REMOTE_NET:=10.30.0.0/24}"

: "${CONTEXT_IPSEC_3_REMOTE:=203.0.113.30}"
: "${CONTEXT_IPSEC_3_PSK:=SecretC}"
: "${CONTEXT_IPSEC_3_LOCALID:=wan}"
: "${CONTEXT_IPSEC_3_LOCAL_NET:=10.10.0.0/24}"
: "${CONTEXT_IPSEC_3_REMOTE_NET:=10.40.0.0/24}"

LOG_FILE="/var/log/context.log"
SCRIPT_VERSION="$(cat /etc/context.d/VERSION 2>/dev/null || echo 'unknown')"
SCRIPT_PATH="$(realpath "$0" 2>/dev/null || echo "$0")"

log() {
  printf '%s [context-IPSEC] %s
' "$(date)" "$*" >> "$LOG_FILE"
}

if [ "${CONTEXT_IPSEC_ENABLE}" != "YES" ]; then
  log "IPsec module disabled via CONTEXT_IPSEC_ENABLE=${CONTEXT_IPSEC_ENABLE} — skipping"
  exit 0
fi

log "=== Starting IPSEC Context (version=${SCRIPT_VERSION}, path=${SCRIPT_PATH}) ==="
# shellcheck shell=sh disable=SC3043,SC1083,SC2086
get_var() {
  local idx="$1" key="$2" var
  var="CONTEXT_IPSEC_${idx}_${key}"
  eval "printf '%s' "\${${var}:-}""
}

# shellcheck shell=sh disable=SC3043
normalize_auth() {
  local value="$1"
  case "$value" in
    hmac_*) printf '%s' "$value" ;;
    sha1|sha256|sha384|sha512) printf 'hmac_%s' "$value" ;;
    *) printf '%s' "$value" ;;
  esac
}

changed_tunnels=0
processed_tunnels=0

for idx in $(seq 1 "$CONTEXT_IPSEC_TUNNELS"); do
  remote="$(get_var "$idx" REMOTE)"
  psk="$(get_var "$idx" PSK)"
  local_if="$(get_var "$idx" LOCALID)"
  local_net="$(get_var "$idx" LOCAL_NET)"
  remote_net="$(get_var "$idx" REMOTE_NET)"
  p1_ike="$(get_var "$idx" P1_IKE)"
  p1_enc_name="$(get_var "$idx" P1_ENC_NAME)"
  p1_enc_keylen="$(get_var "$idx" P1_ENC_KEYLEN)"
  p1_hash="$(get_var "$idx" P1_HASH)"
  p1_dh="$(get_var "$idx" P1_DH)"
  p1_lifetime="$(get_var "$idx" P1_LIFETIME)"
  p2_proto="$(get_var "$idx" P2_PROTO)"
  p2_enc_name="$(get_var "$idx" P2_ENC_NAME)"
  p2_enc_keylen="$(get_var "$idx" P2_ENC_KEYLEN)"
  p2_auth_raw="$(get_var "$idx" P2_AUTH)"
  p2_auth="$(normalize_auth "$p2_auth_raw")"
  p2_pfs="$(get_var "$idx" P2_PFS)"
  p2_lifetime="$(get_var "$idx" P2_LIFETIME)"
   # Логируем, какой туннель сейчас обрабатывается
  log "→ Processing tunnel #${idx} (${local_if} → ${remote})"
  [ -n "$remote" ] || { log "→ Tunnel #${idx}: remote gateway is empty — skipping"; continue; }
  [ -n "$psk" ] || { log "→ Tunnel #${idx}: PSK is empty — skipping"; continue; }
  [ -n "$local_if" ] || { log "→ Tunnel #${idx}: LOCALID is empty — skipping"; continue; }
  [ -n "$local_net" ] || { log "→ Tunnel #${idx}: LOCAL_NET is empty — skipping"; continue; }
  [ -n "$remote_net" ] || { log "→ Tunnel #${idx}: REMOTE_NET is empty — skipping"; continue; }

  processed_tunnels=$((processed_tunnels + 1))
  log "→ Processing tunnel #${idx} (${local_if} → ${remote})"

 result=$(CTX_TUNNEL_INDEX="$idx"     CTX_REMOTE="$remote"     CTX_PSK="$psk"     CTX_LOCALIF="$local_if"     CTX_LOCAL_NET="$local_net"     CTX_REMOTE_NET="$remote_net"     CTX_P1_IKE="$p1_ike"     CTX_P1_ENC_NAME="$p1_enc_name"     CTX_P1_ENC_KEYLEN="$p1_enc_keylen"     CTX_P1_HASH="$p1_hash"     CTX_P1_DH="$p1_dh"     CTX_P1_LIFETIME="$p1_lifetime"     CTX_P2_PROTO="$p2_proto"     CTX_P2_ENC_NAME="$p2_enc_name"     CTX_P2_ENC_KEYLEN="$p2_enc_keylen"     CTX_P2_AUTH="$p2_auth"     CTX_P2_AUTH_RAW="$p2_auth_raw"     CTX_P2_PFS="$p2_pfs"     CTX_P2_LIFETIME="$p2_lifetime"     /usr/local/bin/php <<'PHP'
<?php
declare(strict_types=1);

error_reporting(E_ERROR | E_PARSE);
$logFile = '/var/log/context.log';

global $g;
if (!isset($g) || !is_array($g)) {
    $g = [];
}
$g['disableconfigcache'] = true;
$g['config_post_load'] = true;
require_once('/etc/inc/ipsec.inc');
require_once('/etc/inc/util.inc');

$logFile = '/var/log/context.log';

function ctx_log(string $message): void {
    global $logFile;
    file_put_contents($logFile, sprintf("%s [context-IPSEC][php] %s\n", date('c'), $message), FILE_APPEND);
}

set_error_handler(function (int $errno, string $errstr, string $errfile, int $errline): bool {
    if ((error_reporting() & $errno) === 0) {
        return false;
    }
    ctx_log(sprintf('PHP error %d at %s:%d — %s', $errno, $errfile, $errline, $errstr));
});

$idx = (int) (getenv('CTX_TUNNEL_INDEX') ?: 0);
$remote = trim((string) (getenv('CTX_REMOTE') ?: ''));
$psk = (string) (getenv('CTX_PSK') ?: '');
$localIf = trim((string) (getenv('CTX_LOCALIF') ?: ''));
$localNet = trim((string) (getenv('CTX_LOCAL_NET') ?: ''));
$remoteNet = trim((string) (getenv('CTX_REMOTE_NET') ?: ''));
$p1Ike = strtolower((string) (getenv('CTX_P1_IKE') ?: 'ikev2'));
$p1EncName = strtolower((string) (getenv('CTX_P1_ENC_NAME') ?: 'aes'));
$p1EncKeylen = (int) (getenv('CTX_P1_ENC_KEYLEN') ?: 256);
$p1Hash = strtolower((string) (getenv('CTX_P1_HASH') ?: 'sha256'));
$p1Dh = (string) (getenv('CTX_P1_DH') ?: '14');
$p1Lifetime = (string) (getenv('CTX_P1_LIFETIME') ?: '28800');
$p2Proto = strtolower((string) (getenv('CTX_P2_PROTO') ?: 'esp'));
$p2EncName = strtolower((string) (getenv('CTX_P2_ENC_NAME') ?: 'aes'));
$p2EncKeylen = (int) (getenv('CTX_P2_ENC_KEYLEN') ?: 256);
$p2Auth = strtolower((string) (getenv('CTX_P2_AUTH') ?: 'hmac_sha256'));
$p2Pfs = strtolower((string) (getenv('CTX_P2_PFS') ?: 'off'));
$p2Lifetime = (string) (getenv('CTX_P2_LIFETIME') ?: '3600');

try {
    global $config;

    $changed = false;
    $status = 'unchanged';
    $ikeid = 0;

    if (!isset($config['ipsec']) || !is_array($config['ipsec'])) {
        $config['ipsec'] = [];
    }

    foreach (['phase1', 'phase2', 'pre-shared-key'] as $section) {
        if (!isset($config['ipsec'][$section]) || !is_array($config['ipsec'][$section])) {
            $config['ipsec'][$section] = [];
        }
    }

    $config['ipsec']['enable'] = 'true';

    $localParts = explode('/', $localNet);
    $remoteParts = explode('/', $remoteNet);
    if (count($localParts) !== 2 || count($remoteParts) !== 2) {
        throw new RuntimeException('Invalid CIDR notation for local or remote network');
    }
    [$localAddr, $localBits] = $localParts;
    [$remoteAddr, $remoteBits] = $remoteParts;

    $localAddr = trim($localAddr);
    $remoteAddr = trim($remoteAddr);
    $localBits = trim($localBits);
    $remoteBits = trim($remoteBits);

    if ($localAddr === '' || $remoteAddr === '') {
        throw new RuntimeException('Local or remote network address is empty');
    }

    $existingP1Index = null;
    if (!empty($config['ipsec']['phase1'])) {
        foreach ($config['ipsec']['phase1'] as $idxKey => $phase1) {
            if (($phase1['remote-gateway'] ?? '') === $remote && ($phase1['interface'] ?? '') === $localIf) {
                $existingP1Index = $idxKey;
                break;
            }
        }
    }

    if ($existingP1Index !== null) {
        $ph1 = $config['ipsec']['phase1'][$existingP1Index];
        $ikeid = (int) ($ph1['ikeid'] ?? 0);
    } else {
        $ph1 = [];
        $ikeid = ipsec_ikeid_next();
    }

    $ph1Original = $ph1;

    $ph1['ikeid'] = $ikeid;
    $ph1['iketype'] = $p1Ike;
    if ($p1Ike === 'ikev2') {
        unset($ph1['mode']);
    } else {
        $ph1['mode'] = $ph1['mode'] ?? 'main';
    }
    $ph1['interface'] = $localIf;
    $ph1['remote-gateway'] = $remote;
    $ph1['protocol'] = strpos($remoteAddr, ':') !== false ? 'inet6' : 'inet';
    $ph1['myid_type'] = 'myaddress';
    $ph1['myid_data'] = '';
    $ph1['peerid_type'] = 'peeraddress';
    $ph1['peerid_data'] = $remote;
    $ph1['authentication_method'] = 'pre_shared_key';
    $ph1['pre-shared-key'] = $psk;
    $ph1['descr'] = sprintf('[context] Tunnel #%d %s → %s', $idx, $localIf, $remote);
    $ph1['encryption'] = [
        'item' => [
            [
                'encryption-algorithm' => [
                    'name' => $p1EncName,
                    'keylen' => $p1EncKeylen,
                ],
                'hash-algorithm' => $p1Hash,
                'prf-algorithm' => $p1Hash,
                'dhgroup' => $p1Dh,
            ],
        ],
    ];
    $ph1['lifetime'] = $p1Lifetime;
    $ph1['nat_traversal'] = $ph1['nat_traversal'] ?? 'on';
    $ph1['mobike'] = $ph1['mobike'] ?? 'off';

    // --- Dead Peer Detection (DPD) ---
    $ph1['dpd_enable'] = 'true';     // включает галку "Enable DPD"
    $ph1['dpd_delay']  = '10';     // интервал проверки, сек
    $ph1['dpd_maxfail'] = '5';     // после 5 ошибок peer считается down

    if ($ph1Original !== $ph1) {
        if ($existingP1Index !== null) {
            $config['ipsec']['phase1'][$existingP1Index] = $ph1;
            $status = 'updated';
        } else {
            $config['ipsec']['phase1'][] = $ph1;
            $status = 'created';
        }
        $changed = true;
    }

    $existingP2Index = null;
    if (!empty($config['ipsec']['phase2'])) {
        foreach ($config['ipsec']['phase2'] as $p2Index => $phase2) {
            if (($phase2['ikeid'] ?? null) == $ikeid) {
                $localMatch = ($phase2['localid']['type'] ?? '') === 'network'
                    && ($phase2['localid']['address'] ?? '') === $localAddr
                    && (string) ($phase2['localid']['netbits'] ?? '') === $localBits;
                $remoteMatch = ($phase2['remoteid']['type'] ?? '') === 'network'
                    && ($phase2['remoteid']['address'] ?? '') === $remoteAddr
                    && (string) ($phase2['remoteid']['netbits'] ?? '') === $remoteBits;
                if ($localMatch && $remoteMatch) {
                    $existingP2Index = $p2Index;
                    break;
                }
            }
        }
    }

    if ($existingP2Index !== null) {
        $p2 = $config['ipsec']['phase2'][$existingP2Index];
    } else {
        $p2 = [];
        $p2['reqid'] = ipsec_new_reqid();
        $p2['uniqid'] = uniqid('', true);
    }

    $p2Original = $p2;

    $p2['ikeid'] = $ikeid;
    $p2['mode'] = 'tunnel';
    $p2['disabled'] = false;
    $p2['localid'] = [
        'type' => 'network',
        'address' => $localAddr,
        'netbits' => $localBits,
    ];
    $p2['remoteid'] = [
        'type' => 'network',
        'address' => $remoteAddr,
        'netbits' => $remoteBits,
    ];
    $p2['protocol'] = $p2Proto;
    $p2['encryption-algorithm-option'] = [
        [
            'name' => $p2EncName,
            'keylen' => $p2EncKeylen,
        ],
    ];
    $p2['hash-algorithm-option'] = [$p2Auth];
    $p2['start_action'] = 'start'; //  заставит pfSense инициировать туннель сам
    if ($p2Pfs === '' || $p2Pfs === 'off' || $p2Pfs === 'none') {
        $p2['pfsgroup'] = 'off';
    } else {
        $p2['pfsgroup'] = $p2Pfs;
    }
    $p2['lifetime'] = $p2Lifetime;
    $p2['keepalive'] = 'enabled';
    $p2['descr'] = sprintf('[context] Tunnel #%d %s/%s → %s/%s', $idx, $localAddr, $localBits, $remoteAddr, $remoteBits);

    if ($p2Original !== $p2) {
        if ($existingP2Index !== null) {
            $config['ipsec']['phase2'][$existingP2Index] = $p2;
        } else {
            $config['ipsec']['phase2'][] = $p2;
        }
        $changed = true;
        if ($status === 'unchanged') {
            $status = $existingP2Index !== null ? 'updated' : 'created';
        }
    }

    if ($changed) {
        global $g;
        $g['disableconfigcache'] = true;
        write_config(sprintf('[context-IPSEC] Updated tunnel #%d (%s)', $idx, $remote), false);

    }

    ctx_log(sprintf('Tunnel #%d (%s) status=%s changed=%s ikeid=%d', $idx, $remote, $status, $changed ? 'yes' : 'no', $ikeid));

    echo $status . '|' . ($changed ? '1' : '0') . '|' . $ikeid;
    exit(0);
} catch (Throwable $e) {
    ctx_log(sprintf('Tunnel #%d (%s) failed: %s', $idx, $remote ?: 'n/a', $e->getMessage()));
    echo 'error|0|0';
    exit(1);
}
PHP
  )

  rc=$?
  if [ $rc -ne 0 ]; then
    log "  Tunnel #${idx} failed with exit code $rc"
    continue
  fi

  IFS='|' read -r status changed ikeid <<EOF
${result}
EOF

  case "$status" in
    created)
      log "  Created new tunnel to ${remote} (ikeid=${ikeid})"
      ;;
    updated)
      log "  Updated tunnel to ${remote} (ikeid=${ikeid})"
      ;;
    unchanged)
      log "  Tunnel to ${remote} already up-to-date (ikeid=${ikeid})"
      ;;
    error)
      log "  Error processing tunnel to ${remote} (see PHP log above)"
      ;;
    *)
      log "  Unknown status '${status}' for tunnel to ${remote}"
      ;;
  esac

  if [ "${changed}" = "1" ]; then
    changed_tunnels=$((changed_tunnels + 1))
  fi

done

if [ "$changed_tunnels" -gt 0 ]; then
  log "Applying ipsec_configure() after ${changed_tunnels} change(s)"
  /usr/local/bin/php <<'PHP'
<?php
declare(strict_types=1);
error_reporting(E_ERROR | E_PARSE);
$logFile = '/var/log/context.log';

global $g;
if (!isset($g) || !is_array($g)) {
    $g = [];
}
$g['disableconfigcache'] = true;
unset($g['config_cache_path']);
$g['config_post_load'] = true;
require_once('/etc/inc/util.inc');
require_once('/etc/inc/ipsec.inc');


function ctx_log(string $message): void {
    file_put_contents('/var/log/context.log', sprintf("%s [context-IPSEC][php] %s\n", date('c'), $message), FILE_APPEND);
}


try {
    ipsec_configure();
    ctx_log('ipsec_configure() executed successfully');
} catch (Throwable $e) {
    ctx_log('ipsec_configure() failed: ' . $e->getMessage());
    throw $e;
}
PHP
fi

# --- ensure strongSwan is running ---
log "🔁 Ensuring strongSwan service is running"
/usr/local/bin/php <<'PHP'
<?php
declare(strict_types=1);
require_once('/etc/inc/service-utils.inc');
require_once('/etc/inc/util.inc');

function ctx_log(string $message): void {
    file_put_contents('/var/log/context.log', sprintf("%s [context-IPSEC][php] %s\n", date('c'), $message), FILE_APPEND);
}

try {
    $service = 'ipsec';
    $status = get_service_status(['name' => $service]);
    if ($status !== 'running') {
        mwexec('/usr/local/sbin/ipsec start');
        ctx_log('strongSwan started automatically');
    } else {
        ctx_log('strongSwan already running');
    }
} catch (Throwable $e) {
    ctx_log('Failed to check/start strongSwan: ' . $e->getMessage());
}
PHP

log "🧱 Applying IPsec firewall rules"

/usr/local/bin/php <<'PHP'
<?php
declare(strict_types=1);
error_reporting(E_ERROR | E_PARSE);

require_once('/etc/inc/config.inc');
require_once('/etc/inc/globals.inc');
require_once('/etc/inc/util.inc');
require_once('/etc/inc/ipsec.inc');
require_once('/etc/inc/filter.inc');


function ctx_log(string $msg): void {
    file_put_contents('/var/log/context.log',
        sprintf("%s [context-IPSEC][fw] %s\n", date('c'), $msg),
        FILE_APPEND);
}

global $config;
if (!isset($config['filter']) || !is_array($config['filter'])) $config['filter'] = [];
if (!isset($config['filter']['rule']) || !is_array($config['filter']['rule'])) $config['filter']['rule'] = [];

$rules_added = 0;
$rules_updated = 0;

$phase2 = $config['ipsec']['phase2'] ?? [];
foreach ($phase2 as $p2) {
    // Берём только network→network (policy-based)
    $lid = $p2['localid']  ?? [];
    $rid = $p2['remoteid'] ?? [];
    if (($lid['type'] ?? '') !== 'network' || ($rid['type'] ?? '') !== 'network') {
        continue;
    }

    $localNet  = trim(($lid['address'] ?? '').'/' .($lid['netbits'] ?? ''));
    $remoteNet = trim(($rid['address'] ?? '').'/'.($rid['netbits'] ?? ''));
    if ($localNet === '' || $remoteNet === '') continue;

    $descr = sprintf('[context] IPsec %s → %s', $remoteNet, $localNet);
    $uuid  = md5($descr);

    // Проверяем, есть ли уже такое правило
    $found = false;
    foreach ($config['filter']['rule'] as &$rule) {
        if (($rule['interface'] ?? '') === 'ipsec' && ($rule['descr'] ?? '') === $descr) {
            $rule['source']      = ['network' => $remoteNet];
            $rule['destination'] = ['network' => $localNet];
            $rule['updated']     = date('c');
            $rule['disabled']    = 'no';
            $found = true;
            $rules_updated++;
            ctx_log("Updated rule: $descr");
            break;
        }
    }
    unset($rule);

    if (!$found) {
        $config['filter']['rule'][] = [
            'type'           => 'pass',
            'interface'      => 'ipsec',       // интерфейс в GUI
            'apply_to_ipsec' => 'yes',         // 👈 обязательно для pfSense 2.8+
            'ipprotocol'     => 'inet',
            'protocol'       => 'any',
            'source'         => ['network' => $remoteNet],
            'destination'    => ['network' => $localNet],
            'descr'          => $descr,
            'direction'      => 'any',
            'quick'          => 'yes',
            'log'            => 'yes',
            'disabled'       => 'no',
            'created'        => date('c'),
            'updated'        => date('c'),
            'uuid'           => $uuid,
        ];
        $rules_added++;
        ctx_log("Added rule: $descr");
    }
}

if ($rules_added > 0 || $rules_updated > 0) {
    write_config("[context-IPSEC] Firewall rules (added=$rules_added, updated=$rules_updated)", false);

    // Попробуем мягко перезагрузить фаервол
    if (function_exists('filter_configure_sync')) {
        try {
            @filter_configure_sync();
            ctx_log("Reloaded pf ruleset via filter_configure_sync()");
        } catch (Throwable $e) {
            ctx_log("WARNING: filter_configure_sync() failed: " . $e->getMessage());
            mwexec('/etc/rc.filter_configure');
            ctx_log("Fallback: executed /etc/rc.filter_configure");
        }
    } else {
        ctx_log("filter_configure_sync() not available — calling /etc/rc.filter_configure instead");
        mwexec('/etc/rc.filter_configure');
    }
} else {
    ctx_log("No IPsec firewall rule changes");
}
PHP

log "✅ Completed (Processed=${processed_tunnels}, Changed=${changed_tunnels})"

exit 0