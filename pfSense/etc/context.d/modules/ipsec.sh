#!/bin/sh
set -eu

# ============================================================
# 🔧 DEFAULTS (для отладки без контекста ISO)
# ============================================================

: "${CONTEXT_IPSEC_ENABLE:=YES}"
: "${CONTEXT_IPSEC_TUNNELS:=1}"

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

#: "${CONTEXT_IPSEC_2_REMOTE:=203.0.113.20}"
#: "${CONTEXT_IPSEC_2_PSK:=SecretB}"
#: "${CONTEXT_IPSEC_2_LOCALID:=wan}"
#: "${CONTEXT_IPSEC_2_LOCAL_NET:=10.10.0.0/24}"
#: "${CONTEXT_IPSEC_2_REMOTE_NET:=10.30.0.0/24}"
#
#: "${CONTEXT_IPSEC_3_REMOTE:=203.0.113.30}"
#: "${CONTEXT_IPSEC_3_PSK:=SecretC}"
#: "${CONTEXT_IPSEC_3_LOCALID:=wan}"
#: "${CONTEXT_IPSEC_3_LOCAL_NET:=10.10.0.0/24}"
#: "${CONTEXT_IPSEC_3_REMOTE_NET:=10.40.0.0/24}"

LOG_FILE="/var/log/context.log"
SCRIPT_PATH="$(realpath "$0" 2>/dev/null || echo "$0")"

log() {
  printf '%s [context-IPSEC] %s\n' "$(date)" "$*" >> "$LOG_FILE"
}

if [ "${CONTEXT_IPSEC_ENABLE}" != "YES" ]; then
  log "IPsec module disabled via CONTEXT_IPSEC_ENABLE=${CONTEXT_IPSEC_ENABLE} — skipping"
  exit 0
fi

log "=== Starting IPSEC Context, path=${SCRIPT_PATH}) ==="
 for v in CONTEXT_IPSEC_1_REMOTE CONTEXT_IPSEC_1_PSK CONTEXT_IPSEC_1_LOCALID CONTEXT_IPSEC_1_LOCAL_NET CONTEXT_IPSEC_1_REMOTE_NET; do
  eval "[ -z \"\${$v-}\" ]" && { log "  ERROR: required variable $v is not set — aborting"; return 0; }
done
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

  log "→ Processing tunnel #${idx} (${local_if} → ${remote})"
  [ -n "$remote" ] || { log "→ Tunnel #${idx}: remote gateway is empty — skipping"; continue; }
  [ -n "$psk" ]    || { log "→ Tunnel #${idx}: PSK is empty — skipping"; continue; }
  [ -n "$local_if" ] || { log "→ Tunnel #${idx}: LOCALID is empty — skipping"; continue; }
  [ -n "$local_net" ] || { log "→ Tunnel #${idx}: LOCAL_NET is empty — skipping"; continue; }
  [ -n "$remote_net" ] || { log "→ Tunnel #${idx}: REMOTE_NET is empty — skipping"; continue; }

  processed_tunnels=$((processed_tunnels + 1))

  result=$(
    CTX_TUNNEL_INDEX="$idx" \
    CTX_REMOTE="$remote" \
    CTX_PSK="$psk" \
    CTX_LOCALIF="$local_if" \
    CTX_LOCAL_NET="$local_net" \
    CTX_REMOTE_NET="$remote_net" \
    CTX_P1_IKE="$p1_ike" \
    CTX_P1_ENC_NAME="$p1_enc_name" \
    CTX_P1_ENC_KEYLEN="$p1_enc_keylen" \
    CTX_P1_HASH="$p1_hash" \
    CTX_P1_DH="$p1_dh" \
    CTX_P1_LIFETIME="$p1_lifetime" \
    CTX_P2_PROTO="$p2_proto" \
    CTX_P2_ENC_NAME="$p2_enc_name" \
    CTX_P2_ENC_KEYLEN="$p2_enc_keylen" \
    CTX_P2_AUTH="$p2_auth" \
    CTX_P2_AUTH_RAW="$p2_auth_raw" \
    CTX_P2_PFS="$p2_pfs" \
    CTX_P2_LIFETIME="$p2_lifetime" \
    /usr/local/bin/php <<'PHP'
<?php
declare(strict_types=1);
error_reporting(E_ERROR | E_PARSE);

global $g; if (!isset($g) || !is_array($g)) { $g = []; }
$g['disableconfigcache'] = true;
$g['config_post_load']   = true;

require_once('/etc/inc/ipsec.inc');
require_once('/etc/inc/util.inc');

function ctx_log(string $m): void {
  file_put_contents('/var/log/context.log', date('c')." [context-IPSEC][php] $m\n", FILE_APPEND);
}

$idx        = (int) (getenv('CTX_TUNNEL_INDEX') ?: 0);
$remote     = trim((string) (getenv('CTX_REMOTE') ?: ''));
$psk        = (string) (getenv('CTX_PSK') ?: '');
$localIf    = trim((string) (getenv('CTX_LOCALIF') ?: ''));
$localNet   = trim((string) (getenv('CTX_LOCAL_NET') ?: ''));
$remoteNet  = trim((string) (getenv('CTX_REMOTE_NET') ?: ''));
$p1Ike      = strtolower((string) (getenv('CTX_P1_IKE') ?: 'ikev2'));
$p1EncName  = strtolower((string) (getenv('CTX_P1_ENC_NAME') ?: 'aes'));
$p1EncKeylen= (int) (getenv('CTX_P1_ENC_KEYLEN') ?: 256);
$p1Hash     = strtolower((string) (getenv('CTX_P1_HASH') ?: 'sha256'));
$p1Dh       = (string) (getenv('CTX_P1_DH') ?: '14');
$p1Lifetime = (string) (getenv('CTX_P1_LIFETIME') ?: '28800');
$p2Proto    = strtolower((string) (getenv('CTX_P2_PROTO') ?: 'esp'));
$p2EncName  = strtolower((string) (getenv('CTX_P2_ENC_NAME') ?: 'aes'));
$p2EncKeylen= (int) (getenv('CTX_P2_ENC_KEYLEN') ?: 256);
$p2Auth     = strtolower((string) (getenv('CTX_P2_AUTH') ?: 'hmac_sha256'));
$p2Pfs      = strtolower((string) (getenv('CTX_P2_PFS') ?: 'off'));
$p2Lifetime = (string) (getenv('CTX_P2_LIFETIME') ?: '3600');

try {
  global $config; $changed=false; $status='unchanged'; $ikeid=0;

  if (!isset($config['ipsec']) || !is_array($config['ipsec'])) $config['ipsec'] = [];
  foreach (['phase1','phase2','pre-shared-key'] as $s)
    if (!isset($config['ipsec'][$s]) || !is_array($config['ipsec'][$s])) $config['ipsec'][$s] = [];

  $config['ipsec']['enable'] = 'true';

  $localParts  = explode('/', $localNet);
  $remoteParts = explode('/', $remoteNet);
  if (count($localParts) !== 2 || count($remoteParts) !== 2) throw new RuntimeException('Invalid CIDR');
  [$localAddr, $localBits]   = $localParts;
  [$remoteAddr, $remoteBits] = $remoteParts;
  if ($localAddr==='' || $remoteAddr==='') throw new RuntimeException('Empty network');

  $existingP1Index = null;
  foreach ($config['ipsec']['phase1'] ?? [] as $idxKey => $ph1) {
    if (($ph1['remote-gateway'] ?? '') === $remote && ($ph1['interface'] ?? '') === $localIf) {
      $existingP1Index = $idxKey; break;
    }
  }

  if ($existingP1Index !== null) { $ph1 = $config['ipsec']['phase1'][$existingP1Index]; $ikeid = (int)($ph1['ikeid'] ?? 0); }
  else { $ph1 = []; $ikeid = ipsec_ikeid_next(); }

  $ph1Original = $ph1;
  $ph1['ikeid']           = $ikeid;
  $ph1['iketype']         = $p1Ike;
  if ($p1Ike === 'ikev2') unset($ph1['mode']); else $ph1['mode'] = $ph1['mode'] ?? 'main';
  $ph1['interface']       = $localIf;
  $ph1['remote-gateway']  = $remote;
  $ph1['protocol']        = strpos($remoteAddr, ':') !== false ? 'inet6' : 'inet';
  $ph1['myid_type']       = 'myaddress';
  $ph1['myid_data']       = '';
  $ph1['peerid_type']     = 'peeraddress';
  $ph1['peerid_data']     = $remote;
  $ph1['authentication_method'] = 'pre_shared_key';
  $ph1['pre-shared-key']  = $psk;
  $ph1['descr']           = sprintf('[context] Tunnel #%d %s → %s', $idx, $localIf, $remote);
  $ph1['encryption']      = ['item' => [[
    'encryption-algorithm' => ['name'=>$p1EncName,'keylen'=>$p1EncKeylen],
    'hash-algorithm'       => $p1Hash,
    'prf-algorithm'        => $p1Hash,
    'dhgroup'              => $p1Dh,
  ]]];
  $ph1['lifetime']        = $p1Lifetime;
  $ph1['nat_traversal']   = $ph1['nat_traversal'] ?? 'on';
  $ph1['mobike']          = $ph1['mobike'] ?? 'off';
  $ph1['dpd_enable']      = 'true';
  $ph1['dpd_delay']       = '10';
  $ph1['dpd_maxfail']     = '5';

  if ($ph1Original !== $ph1) { 
    if ($existingP1Index !== null) $config['ipsec']['phase1'][$existingP1Index] = $ph1;
    else $config['ipsec']['phase1'][] = $ph1;
    $changed = true; $status = $existingP1Index !== null ? 'updated' : 'created';
  }

  $existingP2Index = null;
  foreach ($config['ipsec']['phase2'] ?? [] as $p2Index => $phase2) {
    if (($phase2['ikeid'] ?? null) == $ikeid) {
      $localMatch  = ($phase2['localid']['type'] ?? '')==='network'  && ($phase2['localid']['address'] ?? '')===$localAddr  && (string)($phase2['localid']['netbits'] ?? '')===(string)$localBits;
      $remoteMatch = ($phase2['remoteid']['type'] ?? '')==='network' && ($phase2['remoteid']['address'] ?? '')===$remoteAddr && (string)($phase2['remoteid']['netbits'] ?? '')===(string)$remoteBits;
      if ($localMatch && $remoteMatch) { $existingP2Index = $p2Index; break; }
    }
  }

  if ($existingP2Index !== null) $p2 = $config['ipsec']['phase2'][$existingP2Index];
  else { $p2 = []; $p2['reqid'] = ipsec_new_reqid(); $p2['uniqid'] = uniqid('', true); }

  $p2Original = $p2;
  $p2['ikeid']  = $ikeid;
  $p2['mode']   = 'tunnel';
  $p2['disabled'] = false;
  $p2['localid']  = ['type'=>'network','address'=>$localAddr,'netbits'=>$localBits];
  $p2['remoteid'] = ['type'=>'network','address'=>$remoteAddr,'netbits'=>$remoteBits];
  $p2['protocol'] = $p2Proto;
  $p2['encryption-algorithm-option'] = [[ 'name'=>$p2EncName, 'keylen'=>$p2EncKeylen ]];
  $p2['hash-algorithm-option']       = [ $p2Auth ];
  $p2['start_action'] = 'start';
  $p2['pfsgroup']     = ($p2Pfs===''||$p2Pfs==='off'||$p2Pfs==='none') ? 'off' : $p2Pfs;
  $p2['lifetime']     = $p2Lifetime;
  $p2['keepalive']    = 'enabled';
  $p2['descr']        = sprintf('[context] Tunnel #%d %s/%s → %s/%s', $idx, $localAddr, $localBits, $remoteAddr, $remoteBits);

  if ($p2Original !== $p2) {
    if ($existingP2Index !== null) $config['ipsec']['phase2'][$existingP2Index] = $p2;
    else $config['ipsec']['phase2'][] = $p2;
    $changed = true; if ($status==='unchanged') $status = $existingP2Index !== null ? 'updated' : 'created';
  }

  if ($changed) {
    global $g; $g['disableconfigcache'] = true;
    write_config(sprintf('[context-IPSEC] Updated tunnel #%d (%s)', $idx, $remote), false);
  }

  ctx_log(sprintf('Tunnel #%d (%s) status=%s changed=%s ikeid=%d', $idx, $remote, $status, $changed ? 'yes' : 'no', $ikeid));
  echo $status.'|'.($changed ? '1' : '0').'|'.$ikeid;
  exit(0);
} catch (Throwable $e) {
  ctx_log(sprintf('Tunnel #%d (%s) failed: %s', $idx, $remote ?: 'n/a', $e->getMessage()));
  echo 'error|0|0'; exit(1);
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
    created)   log "  Created new tunnel to ${remote} (ikeid=${ikeid})" ;;
    updated)   log "  Updated tunnel to ${remote} (ikeid=${ikeid})" ;;
    unchanged) log "  Tunnel to ${remote} already up-to-date (ikeid=${ikeid})" ;;
    error)     log "  Error processing tunnel to ${remote} (see PHP log above)" ;;
    *)         log "  Unknown status '${status}' for tunnel to ${remote}" ;;
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

global $g; if (!isset($g) || !is_array($g)) { $g = []; }
$g['disableconfigcache'] = true;
unset($g['config_cache_path']);
$g['config_post_load'] = true;

require_once('/etc/inc/util.inc');
require_once('/etc/inc/ipsec.inc');

function ctx_log(string $m): void {
  file_put_contents('/var/log/context.log', date('c')." [context-IPSEC][php] $m\n", FILE_APPEND);
}

try {
  ipsec_configure();
  if (function_exists('send_event')) {
    send_event('service reload ipsec');
    ctx_log('Triggered send_event("service reload ipsec")');
  }
  ctx_log('ipsec_configure() executed successfully');
} catch (Throwable $e) {
  ctx_log('ipsec_configure() failed: '.$e->getMessage());
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

function ctx_log(string $m): void {
  file_put_contents('/var/log/context.log', date('c')." [context-IPSEC][php] $m\n", FILE_APPEND);
}
try {
  $service='ipsec';
  $status=get_service_status(['name'=>$service]);
  if ($status !== 'running') {
    mwexec('/usr/local/sbin/ipsec start');
    ctx_log('strongSwan started automatically');
  } else {
    ctx_log('strongSwan already running');
  }
} catch (Throwable $e) {
  ctx_log('Failed to check/start strongSwan: '.$e->getMessage());
}
PHP
#   ============================================================
#               🧩 Подключаем плагины IPSE        
#   ============================================================
 # shellcheck disable=SC1091
 . /etc/context.d/modules/ipsec-plugins/firewall-rules.sh
# shellcheck disable=SC1091
 . /etc/context.d/modules/ipsec-plugins/strat-nonblok.sh
log "✅ Completed successfully"
return 0