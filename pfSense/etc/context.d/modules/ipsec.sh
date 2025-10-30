#!/bin/sh
# ============================================================================
# Context module: IPsec VPN setup for pfSense using OpenNebula context variables
# ============================================================================
# POSIX sh; persists config via pfSense config.xml (write_config)
# Follows pfSense GUI structure from vpn_ipsec_phase1.php and vpn_ipsec_phase2.php
#
# Usage:
#   - Automatically called by ContextOnly during boot
#   - Can be run manually for debugging: sh /etc/context.d/modules/ipsec.sh
#
# Features:
#   - Idempotent: repeated runs with same settings don't change state
#   - Self-contained: includes default variables for standalone testing
#   - Supports multiple tunnels via CONTEXT_IPSEC_TUNNELS variable
#   - Compatible with pfSense GUI (can edit tunnels after auto-config)
# ============================================================================

set -eu

SCRIPT_VERSION="IPSEC v1.0.0 2025-10-30"
LOG_FILE="/var/log/context.log"

# ============================================================================
# 🔧 DEFAULTS (for debugging without context ISO)
# ============================================================================
# These values are used if not provided by OpenNebula context
# Use := syntax to allow override from environment

: "${CONTEXT_IPSEC_ENABLE:=YES}"
: "${CONTEXT_IPSEC_TUNNELS:=1}"

# --- Tunnel #1 (Policy-based, test) ---
: "${CONTEXT_IPSEC_1_REMOTE:=203.0.113.10}"
: "${CONTEXT_IPSEC_1_PSK:=SuperSecretKey123}"
: "${CONTEXT_IPSEC_1_LOCALID:=wan}"
: "${CONTEXT_IPSEC_1_LOCAL_NET:=10.10.0.0/24}"
: "${CONTEXT_IPSEC_1_REMOTE_NET:=10.20.0.0/24}"

# --- Phase1 (IKE) ---
: "${CONTEXT_IPSEC_1_P1_IKE:=ikev2}"
: "${CONTEXT_IPSEC_1_P1_ENC_NAME:=aes}"
: "${CONTEXT_IPSEC_1_P1_ENC_KEYLEN:=256}"
: "${CONTEXT_IPSEC_1_P1_HASH:=sha256}"
: "${CONTEXT_IPSEC_1_P1_DH:=14}"
: "${CONTEXT_IPSEC_1_P1_LIFETIME:=28800}"

# --- Phase2 (ESP) ---
: "${CONTEXT_IPSEC_1_P2_PROTO:=esp}"
: "${CONTEXT_IPSEC_1_P2_ENC_NAME:=aes}"
: "${CONTEXT_IPSEC_1_P2_ENC_KEYLEN:=256}"
: "${CONTEXT_IPSEC_1_P2_AUTH:=sha256}"
: "${CONTEXT_IPSEC_1_P2_PFS:=off}"
: "${CONTEXT_IPSEC_1_P2_LIFETIME:=3600}"

# ============================================================================
# Helper functions
# ============================================================================

log() {
  printf '%s [context-IPSEC] %s\n' "$(date)" "$*" >> "$LOG_FILE"
}

# Mask password in logs (show first 2 and last 2 chars)
mask_password() {
  v="$1"
  [ -z "$v" ] && { printf -- "-"; return; }
  l=${#v}
  if [ "$l" -le 4 ]; then 
    printf '****'
  else 
    printf '%s****%s' "${v%"${v#???}"}" "${v#"${v%???}"}"
  fi
}

# Hash function for idempotency checks (FreeBSD compatible)
sha256_q() {
  if command -v sha256 >/dev/null 2>&1; then
    sha256 -q
  else
    openssl dgst -sha256 -r | awk '{print $1}'
  fi
}

# ============================================================================
# Main execution
# ============================================================================

log "=== Starting IPSEC Context Module ==="
log "Version: ${SCRIPT_VERSION}"
log "Script path: $(realpath "$0" 2>/dev/null || echo "$0")"

# Check if IPsec is enabled
if [ "${CONTEXT_IPSEC_ENABLE}" != "YES" ]; then
  log "IPSEC disabled by context (CONTEXT_IPSEC_ENABLE != YES), exiting"
  exit 0
fi

# Validate PHP CLI is available
PHPBIN="/usr/local/bin/php"
if [ ! -x "$PHPBIN" ]; then
  log "ERROR: PHP CLI not found at $PHPBIN"
  exit 1
fi

# Get config.xml path
CONF_PATH=$("$PHPBIN" -r "require_once('config.inc'); global \$g; echo (\$g['conf_path'] ?? '/conf');" 2>/dev/null)
[ -z "$CONF_PATH" ] && CONF_PATH="/conf"
log "Config path: ${CONF_PATH}/config.xml"

# ============================================================================
# Load context variables (if running from ContextOnly)
# ============================================================================

CONTEXT_FILE="/mnt/context/context.sh"
if [ -f "$CONTEXT_FILE" ]; then
  # shellcheck source=/dev/null
  . "$CONTEXT_FILE" || true
  log "Loaded context variables from $CONTEXT_FILE"
fi

# ============================================================================
# Idempotency check: compute hash of all tunnel configurations
# ============================================================================

STATE_HASH_FILE="/var/run/context-ipsec.hash"
config_signature=""

log "Processing ${CONTEXT_IPSEC_TUNNELS} tunnel(s)"

# Build signature from all tunnel parameters
i=1
while [ "$i" -le "${CONTEXT_IPSEC_TUNNELS}" ]; do
  # Dynamically get variable names for tunnel #i
  eval "remote=\${CONTEXT_IPSEC_${i}_REMOTE:-}"
  eval "psk=\${CONTEXT_IPSEC_${i}_PSK:-}"
  eval "localid=\${CONTEXT_IPSEC_${i}_LOCALID:-}"
  eval "local_net=\${CONTEXT_IPSEC_${i}_LOCAL_NET:-}"
  eval "remote_net=\${CONTEXT_IPSEC_${i}_REMOTE_NET:-}"
  
  # Phase1 params
  eval "p1_ike=\${CONTEXT_IPSEC_${i}_P1_IKE:-}"
  eval "p1_enc=\${CONTEXT_IPSEC_${i}_P1_ENC_NAME:-}"
  eval "p1_keylen=\${CONTEXT_IPSEC_${i}_P1_ENC_KEYLEN:-}"
  eval "p1_hash=\${CONTEXT_IPSEC_${i}_P1_HASH:-}"
  eval "p1_dh=\${CONTEXT_IPSEC_${i}_P1_DH:-}"
  eval "p1_lifetime=\${CONTEXT_IPSEC_${i}_P1_LIFETIME:-}"
  
  # Phase2 params
  eval "p2_proto=\${CONTEXT_IPSEC_${i}_P2_PROTO:-}"
  eval "p2_enc=\${CONTEXT_IPSEC_${i}_P2_ENC_NAME:-}"
  eval "p2_keylen=\${CONTEXT_IPSEC_${i}_P2_ENC_KEYLEN:-}"
  eval "p2_auth=\${CONTEXT_IPSEC_${i}_P2_AUTH:-}"
  eval "p2_pfs=\${CONTEXT_IPSEC_${i}_P2_PFS:-}"
  eval "p2_lifetime=\${CONTEXT_IPSEC_${i}_P2_LIFETIME:-}"
  
  # Skip if essential params missing
  if [ -z "$remote" ] || [ -z "$psk" ]; then
    log "Tunnel #${i}: skipping (missing REMOTE or PSK)"
    i=$((i + 1))
    continue
  fi
  
  # Log tunnel config (mask PSK)
  log "→ Tunnel #${i}: ${localid} → ${remote}"
  log "  Local subnet: ${local_net}, Remote subnet: ${remote_net}"
  log "  Phase1: ${p1_ike}, ${p1_enc}${p1_keylen}, ${p1_hash}, DH${p1_dh}, lifetime ${p1_lifetime}s"
  log "  Phase2: ${p2_proto}, ${p2_enc}${p2_keylen}, ${p2_auth}, PFS ${p2_pfs}, lifetime ${p2_lifetime}s"
  log "  PSK: $(mask_password "$psk")"
  
  # Hash PSK (don't store plaintext in signature)
  psk_hash=$(printf "%s" "$psk" | sha256_q)
  
  # Append to signature
  config_signature="${config_signature}|T${i}:${remote}:${psk_hash}:${localid}:${local_net}:${remote_net}"
  config_signature="${config_signature}:${p1_ike}:${p1_enc}:${p1_keylen}:${p1_hash}:${p1_dh}:${p1_lifetime}"
  config_signature="${config_signature}:${p2_proto}:${p2_enc}:${p2_keylen}:${p2_auth}:${p2_pfs}:${p2_lifetime}"
  
  i=$((i + 1))
done

# Compute final hash
new_hash=$(printf "%s" "$config_signature" | sha256_q)

# Check if config changed since last run
if [ -f "$STATE_HASH_FILE" ]; then
  old_hash=$(cat "$STATE_HASH_FILE")
  if [ "$old_hash" = "$new_hash" ]; then
    log "No changes detected in IPsec configuration, skipping"
    exit 0
  fi
  log "Configuration changed (hash mismatch), proceeding with update"
fi

# Save new hash
echo "$new_hash" > "$STATE_HASH_FILE"

# ============================================================================
# Generate PHP script to configure IPsec
# ============================================================================

TMPPHP="/tmp/ContextIPsec.$$.php"

cat > "$TMPPHP" <<'PHP_HEADER'
<?php
/*
 * Auto-generated by Context IPSEC module
 * Configures IPsec Phase1 and Phase2 entries in pfSense config.xml
 */

require_once('/etc/inc/config.inc');
require_once('/etc/inc/ipsec.inc');
require_once('/etc/inc/vpn.inc');
require_once('/etc/inc/util.inc');

global $config;

// Initialize IPsec config structure
if (!isset($config['ipsec']) || !is_array($config['ipsec'])) {
    $config['ipsec'] = array();
}
if (!isset($config['ipsec']['phase1']) || !is_array($config['ipsec']['phase1'])) {
    $config['ipsec']['phase1'] = array();
}
if (!isset($config['ipsec']['phase2']) || !is_array($config['ipsec']['phase2'])) {
    $config['ipsec']['phase2'] = array();
}

// Track what we're managing (for idempotency)
$context_tunnels = array();

PHP_HEADER

# ============================================================================
# Add tunnel configurations to PHP script
# ============================================================================

i=1
while [ "$i" -le "${CONTEXT_IPSEC_TUNNELS}" ]; do
  eval "remote=\${CONTEXT_IPSEC_${i}_REMOTE:-}"
  eval "psk=\${CONTEXT_IPSEC_${i}_PSK:-}"
  eval "localid=\${CONTEXT_IPSEC_${i}_LOCALID:-wan}"
  eval "local_net=\${CONTEXT_IPSEC_${i}_LOCAL_NET:-}"
  eval "remote_net=\${CONTEXT_IPSEC_${i}_REMOTE_NET:-}"
  
  eval "p1_ike=\${CONTEXT_IPSEC_${i}_P1_IKE:-ikev2}"
  eval "p1_enc=\${CONTEXT_IPSEC_${i}_P1_ENC_NAME:-aes}"
  eval "p1_keylen=\${CONTEXT_IPSEC_${i}_P1_ENC_KEYLEN:-256}"
  eval "p1_hash=\${CONTEXT_IPSEC_${i}_P1_HASH:-sha256}"
  eval "p1_dh=\${CONTEXT_IPSEC_${i}_P1_DH:-14}"
  eval "p1_lifetime=\${CONTEXT_IPSEC_${i}_P1_LIFETIME:-28800}"
  
  eval "p2_proto=\${CONTEXT_IPSEC_${i}_P2_PROTO:-esp}"
  eval "p2_enc=\${CONTEXT_IPSEC_${i}_P2_ENC_NAME:-aes}"
  eval "p2_keylen=\${CONTEXT_IPSEC_${i}_P2_ENC_KEYLEN:-256}"
  eval "p2_auth=\${CONTEXT_IPSEC_${i}_P2_AUTH:-sha256}"
  eval "p2_pfs=\${CONTEXT_IPSEC_${i}_P2_PFS:-off}"
  eval "p2_lifetime=\${CONTEXT_IPSEC_${i}_P2_LIFETIME:-3600}"
  
  # Skip if essential params missing
  if [ -z "$remote" ] || [ -z "$psk" ]; then
    i=$((i + 1))
    continue
  fi
  
  # Escape single quotes in PSK for PHP
  psk_escaped=$(printf "%s" "$psk" | sed "s/'/\\\\'/g")
  
  # Determine mode (tunnel vs tunnel6 based on local/remote net)
  mode="tunnel"
  case "$local_net" in
    *:*) mode="tunnel6" ;;
  esac
  
  # Generate unique IKE ID (based on remote gateway)
  ikeid_base=$(printf "%s" "$remote" | sha256_q | cut -c1-8)
  
  cat >> "$TMPPHP" <<PHP_TUNNEL

// ============================================================================
// Tunnel #${i}: ${localid} → ${remote}
// ============================================================================

\$tunnel_remote = '${remote}';
\$tunnel_psk = '${psk_escaped}';
\$tunnel_descr = 'Context Tunnel #${i} to ${remote}';

// Check if Phase1 already exists (by remote-gateway)
\$p1_index = null;
foreach (\$config['ipsec']['phase1'] as \$idx => \$p1) {
    if (isset(\$p1['remote-gateway']) && \$p1['remote-gateway'] === \$tunnel_remote) {
        \$p1_index = \$idx;
        echo "INFO: Phase1 to {\$tunnel_remote} already exists at index {\$idx}\n";
        break;
    }
}

// Create or update Phase1
if (\$p1_index === null) {
    // Generate new ikeid (pfSense uses sequential IDs, but we'll use hash-based for stability)
    \$ikeid = hexdec('${ikeid_base}') % 1000000;
    \$p1_index = count(\$config['ipsec']['phase1']);
    echo "INFO: Creating new Phase1 to {\$tunnel_remote} (ikeid={\$ikeid})\n";
    
    \$config['ipsec']['phase1'][\$p1_index] = array(
        'ikeid' => \$ikeid,
        'iketype' => '${p1_ike}',
        'interface' => '${localid}',
        'remote-gateway' => \$tunnel_remote,
        'protocol' => 'inet',
        'myid_type' => 'myaddress',
        'peerid_type' => 'peeraddress',
        'authentication_method' => 'pre_shared_key',
        'pre-shared-key' => \$tunnel_psk,
        'lifetime' => '${p1_lifetime}',
        'nat_traversal' => 'on',
        'dpd_enable' => 'on',
        'dpd_delay' => '10',
        'dpd_maxfail' => '5',
        'descr' => \$tunnel_descr,
    );
    
    // Phase1 encryption proposal (follows pfSense array structure)
    \$config['ipsec']['phase1'][\$p1_index]['encryption'] = array(
        'item' => array(
            array(
                'encryption-algorithm' => array(
                    'name' => '${p1_enc}',
                    'keylen' => '${p1_keylen}'
                ),
                'hash-algorithm' => '${p1_hash}',
                'dhgroup' => '${p1_dh}'
            )
        )
    );
} else {
    // Update existing Phase1 (idempotent updates)
    \$ikeid = \$config['ipsec']['phase1'][\$p1_index]['ikeid'];
    echo "INFO: Updating existing Phase1 to {\$tunnel_remote} (ikeid={\$ikeid})\n";
    
    \$config['ipsec']['phase1'][\$p1_index]['iketype'] = '${p1_ike}';
    \$config['ipsec']['phase1'][\$p1_index]['pre-shared-key'] = \$tunnel_psk;
    \$config['ipsec']['phase1'][\$p1_index]['lifetime'] = '${p1_lifetime}';
    \$config['ipsec']['phase1'][\$p1_index]['descr'] = \$tunnel_descr;
    
    // Update encryption proposal
    \$config['ipsec']['phase1'][\$p1_index]['encryption'] = array(
        'item' => array(
            array(
                'encryption-algorithm' => array(
                    'name' => '${p1_enc}',
                    'keylen' => '${p1_keylen}'
                ),
                'hash-algorithm' => '${p1_hash}',
                'dhgroup' => '${p1_dh}'
            )
        )
    );
}

// ============================================================================
// Phase2 for tunnel #${i}
// ============================================================================

// Parse local/remote networks
\$local_net = '${local_net}';
\$remote_net = '${remote_net}';

// Check if Phase2 already exists (by ikeid + local/remote subnets)
\$p2_index = null;
foreach (\$config['ipsec']['phase2'] as \$idx => \$p2) {
    if (isset(\$p2['ikeid']) && \$p2['ikeid'] == \$ikeid) {
        // Check if subnets match
        \$p2_local = isset(\$p2['localid']['address']) ? \$p2['localid']['address'] . '/' . \$p2['localid']['netbits'] : '';
        \$p2_remote = isset(\$p2['remoteid']['address']) ? \$p2['remoteid']['address'] . '/' . \$p2['remoteid']['netbits'] : '';
        
        if (\$p2_local === \$local_net && \$p2_remote === \$remote_net) {
            \$p2_index = \$idx;
            echo "INFO: Phase2 for tunnel #${i} already exists at index {\$idx}\n";
            break;
        }
    }
}

// Parse subnet (address/netbits)
list(\$local_addr, \$local_bits) = explode('/', \$local_net);
list(\$remote_addr, \$remote_bits) = explode('/', \$remote_net);

if (\$p2_index === null) {
    // Create new Phase2
    \$p2_index = count(\$config['ipsec']['phase2']);
    \$uniqid = uniqid();
    echo "INFO: Creating new Phase2 for tunnel #${i} (uniqid={\$uniqid})\n";
    
    \$config['ipsec']['phase2'][\$p2_index] = array(
        'ikeid' => \$ikeid,
        'uniqid' => \$uniqid,
        'mode' => '${mode}',
        'protocol' => '${p2_proto}',
        'localid' => array(
            'type' => 'network',
            'address' => \$local_addr,
            'netbits' => \$local_bits
        ),
        'remoteid' => array(
            'type' => 'network',
            'address' => \$remote_addr,
            'netbits' => \$remote_bits
        ),
        'lifetime' => '${p2_lifetime}',
        'pfsgroup' => '${p2_pfs}',
        'descr' => \$tunnel_descr . ' (P2)',
    );
    
    // Phase2 encryption algorithms (array format)
    \$config['ipsec']['phase2'][\$p2_index]['encryption-algorithm-option'] = array(
        array(
            'name' => '${p2_enc}',
            'keylen' => '${p2_keylen}'
        )
    );
    
    // Phase2 hash algorithms
    \$config['ipsec']['phase2'][\$p2_index]['hash-algorithm-option'] = array('${p2_auth}');
    
} else {
    // Update existing Phase2
    echo "INFO: Updating existing Phase2 for tunnel #${i}\n";
    
    \$config['ipsec']['phase2'][\$p2_index]['mode'] = '${mode}';
    \$config['ipsec']['phase2'][\$p2_index]['protocol'] = '${p2_proto}';
    \$config['ipsec']['phase2'][\$p2_index]['lifetime'] = '${p2_lifetime}';
    \$config['ipsec']['phase2'][\$p2_index]['pfsgroup'] = '${p2_pfs}';
    \$config['ipsec']['phase2'][\$p2_index]['descr'] = \$tunnel_descr . ' (P2)';
    
    \$config['ipsec']['phase2'][\$p2_index]['localid'] = array(
        'type' => 'network',
        'address' => \$local_addr,
        'netbits' => \$local_bits
    );
    
    \$config['ipsec']['phase2'][\$p2_index]['remoteid'] = array(
        'type' => 'network',
        'address' => \$remote_addr,
        'netbits' => \$remote_bits
    );
    
    \$config['ipsec']['phase2'][\$p2_index]['encryption-algorithm-option'] = array(
        array(
            'name' => '${p2_enc}',
            'keylen' => '${p2_keylen}'
        )
    );
    
    \$config['ipsec']['phase2'][\$p2_index]['hash-algorithm-option'] = array('${p2_auth}');
}

\$context_tunnels[] = array('remote' => \$tunnel_remote, 'ikeid' => \$ikeid);

PHP_TUNNEL

  i=$((i + 1))
done

# ============================================================================
# Finalize PHP script
# ============================================================================

cat >> "$TMPPHP" <<'PHP_FOOTER'

// ============================================================================
// Save configuration and apply
// ============================================================================

echo "INFO: Saving configuration...\n";
write_config('Context: IPsec tunnels configured via context module');

// Enable IPsec globally
if (!isset($config['ipsec']['enable'])) {
    $config['ipsec']['enable'] = 'yes';
    write_config('Context: Enabled IPsec globally');
}

echo "SUCCESS: IPsec configuration completed\n";
echo "Configured " . count($context_tunnels) . " tunnel(s)\n";

// Apply IPsec configuration (reload strongSwan)
echo "INFO: Applying IPsec configuration...\n";
if (function_exists('ipsec_configure')) {
    ipsec_configure();
    echo "INFO: IPsec configuration applied\n";
} else {
    echo "WARNING: ipsec_configure() function not available\n";
}

?>
PHP_FOOTER

# ============================================================================
# Execute PHP script
# ============================================================================

log "Executing PHP configuration script..."

if ! "$PHPBIN" -d display_errors=1 "$TMPPHP" >> "$LOG_FILE" 2>&1; then
  log "ERROR: PHP script failed, check $LOG_FILE for details"
  log "PHP script preserved at: $TMPPHP"
  exit 1
fi

# Clean up
rm -f "$TMPPHP"
log "PHP script executed successfully"

# ============================================================================
# Apply IPsec configuration (reload strongSwan)
# ============================================================================

log "Reloading IPsec configuration via vpn_ipsec_configure()..."

"$PHPBIN" -r '
require_once("/etc/inc/ipsec.inc");
require_once("/etc/inc/vpn.inc");
require_once("/etc/inc/filter.inc");

if (function_exists("vpn_ipsec_configure")) {
    vpn_ipsec_configure();
    echo "IPsec configuration reloaded\n";
} else if (function_exists("ipsec_configure")) {
    ipsec_configure();
    echo "IPsec configuration reloaded (legacy)\n";
} else {
    echo "WARNING: No IPsec configure function found\n";
}

// Reload filter rules (for IPsec traffic)
filter_configure();
' >> "$LOG_FILE" 2>&1 || log "WARNING: Failed to reload IPsec/filter"

# ============================================================================
# Completion
# ============================================================================

log "✅ Completed IPSEC Context Module"
log "Tunnels configured: ${CONTEXT_IPSEC_TUNNELS}"
log "Configuration saved to ${CONF_PATH}/config.xml"
log "Review in GUI: VPN > IPsec"

exit 0
