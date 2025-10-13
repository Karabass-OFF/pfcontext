#!/bin/sh
# Context firewall module for pfSense 2.8-RELEASE / OpenNebula

set -eu
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH

SCRIPT_NAME="context-firewall"
SCRIPT_PATH="/etc/context.d/firewall/firewall.sh"
SCRIPT_MODE="executed"
case "${0##*/}" in
  firewall.sh) SCRIPT_MODE="executed" ;;
  *) SCRIPT_MODE="sourced" ;;
esac

LOG_FILE="/var/log/context-firewall.log"
STATE_FILE="/var/run/context-firewall.state"
LOCK_FILE="/var/run/context-firewall.lock"
LOCK_TTL=600

PHP_BIN="/usr/local/bin/php"
XML_BIN="/usr/local/bin/xml"
PFSSH="/usr/local/sbin/pfSsh.php"
PFCTL="/sbin/pfctl"

WORK_XML=""
XML_FILE="/cf/conf/config.xml"
BACKUP_PATH=""
FIREWALL_DEBUG="${FIREWALL_DEBUG:-off}"
FIREWALL_ENABLE="${FIREWALL_ENABLE:-off}"
FIREWALL_PFCTL="${FIREWALL_PFCTL:-on}"
FIREWALL_RELOAD="${FIREWALL_RELOAD:-auto}"

EXIT_STATUS=0

# --- 2) Common functions -----------------------------------------

# log() writes a timestamped message with a severity prefix into the
# module-specific log file, ensuring all actions are auditable.
log() {
  level="$1"
  shift
  ts=$(date '+%Y-%m-%d %H:%M:%S')
  msg="$*"
  printf '%s [%s] %s\n' "$ts" "$level" "$msg" >>"$LOG_FILE"
}

# debug() is a wrapper around log() that respects FIREWALL_DEBUG.
debug() {
  [ "${FIREWALL_DEBUG:-off}" = "on" ] || return 0
  log "DEBUG" "$*"
}

# check_tool() verifies availability of required executables.
check_tool() {
  tool="$1"
  path="$2"
  if [ -n "$path" ] && [ -x "$path" ]; then
    return 0
  fi
  if command -v "$tool" >/dev/null 2>&1; then
    return 0
  fi
  log "ERROR" "Dependency $tool not found"
  return 1
}

# sha256_str() normalises hashing depending on available utilities.
sha256_str() {
  if command -v sha256 >/dev/null 2>&1; then
    sha256 -q
  else
    openssl dgst -sha256 -r | awk '{print $1}'
  fi
}

# cleanup_lock() tears down the lock file and signal traps.
cleanup_lock() {
  rm -f "$LOCK_FILE"
  trap - EXIT INT TERM 2>/dev/null || true
}

# create_lock() ensures single execution with TTL enforcement.
create_lock() {
  if [ -f "$LOCK_FILE" ]; then
    now=$(date +%s)
    mtime=$(stat -f %m "$LOCK_FILE" 2>/dev/null || echo 0)
    if [ "$mtime" -ne 0 ] && [ $((now - mtime)) -lt $LOCK_TTL ]; then
      log "WARN" "Lock file $LOCK_FILE is active (PID=$(cat "$LOCK_FILE" 2>/dev/null))."
      return 1
    fi
    log "WARN" "Removing stale lock file $LOCK_FILE"
    rm -f "$LOCK_FILE"
  fi
  echo "$$" >"$LOCK_FILE"
  trap 'cleanup_lock' EXIT INT TERM
  return 0
}

# backup_xml() creates a dated backup of the active configuration.
backup_xml() {
  ts=$(date '+%Y%m%d%H%M%S')
  BACKUP_PATH="/cf/conf/backup/config.xml.firewall.$ts"
  if ! cp "$XML_FILE" "$BACKUP_PATH" 2>/dev/null; then
    log "ERROR" "Unable to create backup at $BACKUP_PATH"
    return 1
  fi
  log "INFO" "Created backup $BACKUP_PATH"
  return 0
}

# restore_xml() attempts to roll back configuration on failure.
restore_xml() {
  if [ -n "$BACKUP_PATH" ] && [ -f "$BACKUP_PATH" ]; then
    log "WARN" "[rollback] Restoring configuration from $BACKUP_PATH"
    cp "$BACKUP_PATH" "$XML_FILE"
  fi
  [ -f "$WORK_XML" ] || return 0
  cp "$XML_FILE" "$WORK_XML" 2>/dev/null || true
  return 0
}

# normalize_space_list() returns a sorted, de-duplicated newline list.
normalize_space_list() {
  input="$1"
  printf '%s' "$input" | tr ',;' '  ' | tr '\t' ' ' | tr -s ' ' '\n' | sed '/^$/d' | sort -u
}

# write_state() persists the last applied state hash for idempotency.
write_state() {
  state="$1"
  printf '%s' "$state" >"$STATE_FILE"
}

# --- 1) Load variables -------------------------------------------

# load_context_variables() sources the OpenNebula context script,
# synchronises defaults, and points the module at the working XML
# copy prepared by ContextOnly.
load_context_variables() {
  CONTEXT_FILE="/mnt/context/context.sh"
  if [ -z "${FIREWALL_ENABLE+x}" ] && [ -r "$CONTEXT_FILE" ]; then
    # shellcheck source=/dev/null
    . "$CONTEXT_FILE"
  fi
  if [ -z "${backup_xml_file:-}" ]; then
    if [ -f "$XML_FILE" ]; then
      backup_xml_file="/tmp/context-firewall.$$.xml"
      cp "$XML_FILE" "$backup_xml_file"
    fi
  fi
  if [ -z "${backup_xml_file:-}" ] || [ ! -f "$backup_xml_file" ]; then
    log "ERROR" "No backup XML file available"
    return 1
  fi
  WORK_XML="$backup_xml_file"
  FIREWALL_ENABLE="${FIREWALL_ENABLE:-off}"
  FIREWALL_PFCTL="${FIREWALL_PFCTL:-on}"
  FIREWALL_RELOAD="${FIREWALL_RELOAD:-auto}"
  FIREWALL_LOG="${FIREWALL_LOG:-off}"
  FIREWALL_DEFAULT_FORWARD="${FIREWALL_DEFAULT_FORWARD:-deny}"
  FIREWALL_NAT_OUT_IF="${FIREWALL_NAT_OUT_IF:-}" 
  FIREWALL_NAT_NETS="${FIREWALL_NAT_NETS:-}" 
  FIREWALL_NAT_HOSTS="${FIREWALL_NAT_HOSTS:-}" 
  FIREWALL_NAT_ALLOW_NETS="${FIREWALL_NAT_ALLOW_NETS:-}" 
  FIREWALL_BLOCK_NETS="${FIREWALL_BLOCK_NETS:-}" 
  FIREWALL_FORWARD_ALLOW_IF="${FIREWALL_FORWARD_ALLOW_IF:-}" 
  FIREWALL_FORWARD_ALLOW_IP="${FIREWALL_FORWARD_ALLOW_IP:-}" 
  FIREWALL_PORT_FORWARD_LIST="${FIREWALL_PORT_FORWARD_LIST:-}" 
  FIREWALL_DEBUG="${FIREWALL_DEBUG:-off}"
  export FIREWALL_ENABLE FIREWALL_PFCTL FIREWALL_RELOAD FIREWALL_LOG \
    FIREWALL_DEFAULT_FORWARD FIREWALL_NAT_OUT_IF FIREWALL_NAT_NETS \
    FIREWALL_NAT_HOSTS FIREWALL_NAT_ALLOW_NETS FIREWALL_BLOCK_NETS \
    FIREWALL_FORWARD_ALLOW_IF FIREWALL_FORWARD_ALLOW_IP \
    FIREWALL_PORT_FORWARD_LIST FIREWALL_DEBUG
  return 0
}

# --- 3) NAT / outbound NAT ---------------------------------------

# prepare_nat_signature() derives a deterministic signature from the
# outbound NAT inputs so we can decide whether changes are required.
prepare_nat_signature() {
  nets=$(normalize_space_list "$FIREWALL_NAT_NETS")
  hosts=$(normalize_space_list "$FIREWALL_NAT_HOSTS")
  allow=$(normalize_space_list "$FIREWALL_NAT_ALLOW_NETS")
  printf 'iface=%s\n' "$FIREWALL_NAT_OUT_IF"
  printf 'nets='
  printf '%s' "$nets" | tr '\n' ','
  printf '\nhosts='
  printf '%s' "$hosts" | tr '\n' ','
  printf '\nallow='
  printf '%s' "$allow" | tr '\n' ','
  printf '\n'
}

# --- 4) DNAT / Port Forwards -------------------------------------

# normalize_port_forwards() sanitises the semicolon/comma separated
# list before PHP performs the detailed parsing.
normalize_port_forwards() {
  list="$FIREWALL_PORT_FORWARD_LIST"
  printf '%s' "$list" | tr '\n' ' ' | sed 's/;\+/;/g' | sed 's/,\+/,/g'
}

# --- 5) Forward rules --------------------------------------------

# prepare_forward_signature() computes an idempotent signature based
# on allow/block lists and logging options for comparison purposes.
prepare_forward_signature() {
  ifaces=$(printf '%s' "$FIREWALL_FORWARD_ALLOW_IF" | tr ',' ' ' | tr -s ' ' '\n' | sed '/^$/d' | sort -u)
  ips=$(printf '%s' "$FIREWALL_FORWARD_ALLOW_IP" | tr ',' '\n' | sed '/^$/d' | sort -u)
  blocks=$(normalize_space_list "$FIREWALL_BLOCK_NETS")
  printf 'ifaces='
  printf '%s' "$ifaces" | tr '\n' ','
  printf '\nips='
  printf '%s' "$ips" | tr '\n' ','
  printf '\nblocks='
  printf '%s' "$blocks" | tr '\n' ','
  printf '\ndefault=%s\nlog=%s\n' "$FIREWALL_DEFAULT_FORWARD" "$FIREWALL_LOG"
}

# --- 6) Validation & Apply ---------------------------------------
# run_php_helper() executes an embedded PHP helper that performs the
# heavy XML manipulations and returns a change summary or state hash.
run_php_helper() {
  mode="$1"
  script=$(mktemp -t contextfw.XXXXXX)
  cat <<'PHP' >"$script"
<?php
function env_value(string $name): string {
    return trim((string) getenv($name));
}
// parse_space_list() normalises whitespace/semicolon separated values.
function parse_space_list(string $value): array {
    $value = trim(preg_replace('/[\s,;]+/', ' ', $value));
    if ($value === '') {
        return [];
    }
    $parts = preg_split('/\s+/', $value) ?: [];
    $clean = [];
    foreach ($parts as $item) {
        $item = trim($item);
        if ($item !== '') {
            $clean[] = $item;
        }
    }
    $clean = array_values(array_unique($clean));
    sort($clean, SORT_NATURAL);
    return $clean;
}
// parse_comma_list() extracts comma-separated entries into a sorted array.
function parse_comma_list(string $value): array {
    $value = trim($value);
    if ($value === '') {
        return [];
    }
    $parts = preg_split('/\s*,\s*/', $value) ?: [];
    $out = [];
    foreach ($parts as $item) {
        $item = trim($item);
        if ($item !== '') {
            $out[] = $item;
        }
    }
    $out = array_values(array_unique($out));
    sort($out, SORT_NATURAL);
    return $out;
}
// parse_port_forward_list() builds associative arrays from forward entries.
function parse_port_forward_list(string $value): array {
    $value = trim($value);
    if ($value === '') {
        return [];
    }
    $entries = preg_split('/\s*;\s*/', $value) ?: [];
    $result = [];
    foreach ($entries as $entry) {
        $entry = trim($entry);
        if ($entry === '') {
            continue;
        }
        $pairs = preg_split('/\s*,\s*/', $entry) ?: [];
        $assoc = [];
        foreach ($pairs as $pair) {
            if ($pair === '') {
                continue;
            }
            $kv = explode('=', $pair, 2);
            $key = trim($kv[0]);
            $val = isset($kv[1]) ? trim($kv[1]) : '';
            if ($key === '') {
                continue;
            }
            $assoc[$key] = $val;
        }
        if (!isset($assoc['if'])) {
            $assoc['if'] = 'wan';
        }
        if (!isset($assoc['proto']) || $assoc['proto'] === '') {
            $assoc['proto'] = 'tcp';
        }
        if (!isset($assoc['descr']) || $assoc['descr'] === '') {
            $assoc['descr'] = $assoc['if'] . ':' . ($assoc['ext_port'] ?? 'auto');
        }
        $result[] = $assoc;
    }
    usort($result, function (array $a, array $b): int {
        $left = json_encode($a, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $right = json_encode($b, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        return strcmp((string)$left, (string)$right);
    });
    return $result;
}
// build_state_string() constructs a stable hashable representation.
function build_state_string(array $data): string {
    $parts = [];
    $parts[] = 'nat-if=' . ($data['nat_out_if'] ?? '');
    $parts[] = 'nat-nets=' . implode(',', $data['nat_nets']);
    $parts[] = 'nat-hosts=' . implode(',', $data['nat_hosts']);
    $parts[] = 'nat-allow=' . implode(',', $data['nat_allow']);
    $pfParts = [];
    foreach ($data['port_forwards'] as $item) {
        ksort($item);
        $pfParts[] = http_build_query($item, '', '&');
    }
    $parts[] = 'pf=' . implode('|', $pfParts);
    $parts[] = 'allow-if=' . implode(',', $data['forward_if']);
    $parts[] = 'allow-ip=' . implode(',', $data['forward_ip']);
    $parts[] = 'block-nets=' . implode(',', $data['block_nets']);
    $parts[] = 'default=' . ($data['default_forward'] ?? '');
    $parts[] = 'log=' . ($data['log'] ?? '');
    return implode(';', $parts);
}
if (!function_exists('str_starts_with')) {
    function str_starts_with(string $haystack, string $needle): bool {
        return substr($haystack, 0, strlen($needle)) === $needle;
    }
}
// ensure_prefix() prepends ContextFW: to descriptions when missing.
function ensure_prefix(string $descr): string {
    if (str_starts_with($descr, 'ContextFW:')) {
        return $descr;
    }
    return 'ContextFW:' . $descr;
}
// ensure_simplexml() guarantees the presence of a named child node.
function ensure_simplexml(SimpleXMLElement $parent, string $name): SimpleXMLElement {
    if (!isset($parent->{$name})) {
        return $parent->addChild($name);
    }
    return $parent->{$name};
}
$mode = $argv[1] ?? 'state';
$xmlPath = $argv[2] ?? '';
$data = [
    'nat_out_if' => env_value('FIREWALL_NAT_OUT_IF'),
    'nat_nets' => parse_space_list(env_value('FIREWALL_NAT_NETS')),
    'nat_hosts' => parse_space_list(env_value('FIREWALL_NAT_HOSTS')),
    'nat_allow' => parse_space_list(env_value('FIREWALL_NAT_ALLOW_NETS')),
    'port_forwards' => parse_port_forward_list(env_value('FIREWALL_PORT_FORWARD_LIST')),
    'forward_if' => parse_comma_list(env_value('FIREWALL_FORWARD_ALLOW_IF')),
    'forward_ip' => parse_comma_list(env_value('FIREWALL_FORWARD_ALLOW_IP')),
    'block_nets' => parse_space_list(env_value('FIREWALL_BLOCK_NETS')),
    'default_forward' => strtolower(env_value('FIREWALL_DEFAULT_FORWARD')),
    'log' => strtolower(env_value('FIREWALL_LOG')),
];
if ($mode === 'state') {
    echo build_state_string($data);
    exit(0);
}
if ($xmlPath === '' || !file_exists($xmlPath)) {
    fwrite(STDERR, "Missing XML file\n");
    exit(2);
}
libxml_use_internal_errors(true);
$xml = simplexml_load_file($xmlPath);
if ($xml === false) {
    fwrite(STDERR, "Unable to load XML\n");
    exit(3);
}
$summary = [];
$nat = ensure_simplexml($xml, 'nat');
$outbound = ensure_simplexml($nat, 'outbound');
if (!isset($outbound->mode) || (string)$outbound->mode === '') {
    $outbound->mode = 'hybrid';
} else {
    $outbound->mode = 'hybrid';
}
// Drop previously generated ContextFW outbound rules to ensure a clean rebuild.
if (isset($outbound->rule)) {
    foreach ($outbound->rule as $idx => $rule) {
        $descr = (string)$rule->descr;
        if ($descr !== '' && str_starts_with($descr, 'ContextFW:')) {
            $summary[] = 'REMOVED|nat-outbound|' . $descr;
            unset($outbound->rule[$idx]);
        }
    }
}
$iface = $data['nat_out_if'];
// Recreate outbound NAT rules for configured networks.
foreach ($data['nat_nets'] as $net) {
    if ($iface === '') {
        continue;
    }
    $rule = $outbound->addChild('rule');
    $rule->addChild('interface', $iface);
    $src = $rule->addChild('source');
    if (strpos($net, '/') !== false) {
        $src->addChild('network', $net);
    } else {
        $src->addChild('address', $net);
    }
    $rule->addChild('descr', ensure_prefix('NAT ' . $net . ' via ' . $iface));
    $rule->addChild('target');
    $rule->addChild('natport', '0');
    $rule->addChild('sourceport', '0');
    $rule->addChild('dstport', '0');
    $dst = $rule->addChild('destination');
    $dst->addChild('any');
    $summary[] = 'ADDED|nat-outbound|' . (string)$rule->descr;
}
// Add explicit host NAT rules where requested.
foreach ($data['nat_hosts'] as $host) {
    if ($iface === '') {
        continue;
    }
    $rule = $outbound->addChild('rule');
    $rule->addChild('interface', $iface);
    $src = $rule->addChild('source');
    $src->addChild('address', $host);
    $rule->addChild('descr', ensure_prefix('NAT host ' . $host . ' via ' . $iface));
    $rule->addChild('target');
    $rule->addChild('natport', '0');
    $rule->addChild('sourceport', '0');
    $rule->addChild('dstport', '0');
    $dst = $rule->addChild('destination');
    $dst->addChild('any');
    $summary[] = 'ADDED|nat-outbound|' . (string)$rule->descr;
}
// Insert non-NAT bypass rules for networks that must be excluded.
foreach ($data['nat_allow'] as $net) {
    if ($iface === '') {
        continue;
    }
    $rule = $outbound->addChild('rule');
    $rule->addChild('interface', $iface);
    $rule->addChild('nonat');
    $src = $rule->addChild('source');
    if (strpos($net, '/') !== false) {
        $src->addChild('network', $net);
    } else {
        $src->addChild('address', $net);
    }
    $dst = $rule->addChild('destination');
    $dst->addChild('any');
    $rule->addChild('descr', ensure_prefix('NonNAT ' . $net . ' via ' . $iface));
    $summary[] = 'ADDED|nat-outbound|' . (string)$rule->descr;
}
// Purge old DNAT rules owned by this module before rebuilding.
if (isset($nat->rule)) {
    foreach ($nat->rule as $idx => $rule) {
        $descr = (string)$rule->descr;
        if ($descr !== '' && str_starts_with($descr, 'ContextFW:')) {
            $summary[] = 'REMOVED|port-forward|' . $descr;
            unset($nat->rule[$idx]);
        }
    }
}
$assocRules = [];
$pfIndex = 0;
// Build port forward rules based on the parsed context entries.
foreach ($data['port_forwards'] as $entry) {
    $pfIndex++;
    $rule = $nat->addChild('rule');
    $ifc = $entry['if'] ?? 'wan';
    $proto = $entry['proto'] ?? 'tcp';
    $extAddr = $entry['ext_addr'] ?? 'wanaddress';
    $extPort = $entry['ext_port'] ?? '';
    $intIp = $entry['int_ip'] ?? '';
    $intPort = $entry['int_port'] ?? '';
    $baseDescr = $entry['descr'] ?? ($ifc . ':' . ($extPort !== '' ? $extPort : 'auto'));
    $descr = ensure_prefix('PF ' . $baseDescr);
    $rule->addChild('interface', $ifc);
    $rule->addChild('protocol', $proto);
    $src = $rule->addChild('source');
    $src->addChild('any');
    $dst = $rule->addChild('destination');
    if ($extAddr === 'wanaddress' || $extAddr === 'interface-address') {
        $dst->addChild('network', 'wanaddress');
    } elseif ($extAddr !== '') {
        $dst->addChild('address', $extAddr);
    } else {
        $dst->addChild('any');
    }
    if ($extPort !== '') {
        $dst->addChild('port', $extPort);
    }
    if ($intIp !== '') {
        $rule->addChild('target', $intIp);
    }
    if ($intPort !== '') {
        $rule->addChild('local-port', $intPort);
    }
    if (isset($entry['reflection']) && strtolower($entry['reflection']) === 'off') {
        $rule->addChild('noreflect');
    }
    if (isset($entry['disabled']) && in_array(strtolower($entry['disabled']), ['on', 'yes', 'true', '1'], true)) {
        $rule->addChild('disabled');
    }
    $assocId = 'ContextFW-PF-' . $pfIndex;
    if (isset($entry['assoc_rule']) && strtolower($entry['assoc_rule']) === 'pass') {
        $rule->addChild('associated-rule-id', $assocId);
        $assocRules[] = [
            'id' => $assocId,
            'interface' => $ifc,
            'proto' => $proto,
            'src' => $entry['src'] ?? 'any',
            'dst_ip' => $intIp,
            'dst_port' => $intPort,
            'label' => $baseDescr,
        ];
    }
    $rule->addChild('descr', $descr);
    $summary[] = 'ADDED|port-forward|' . $descr;
}
$filter = ensure_simplexml($xml, 'filter');
// Remove historical filter rules created by the firewall module.
if (isset($filter->rule)) {
    foreach ($filter->rule as $idx => $rule) {
        $descr = (string)$rule->descr;
        if ($descr !== '' && str_starts_with($descr, 'ContextFW:')) {
            $summary[] = 'REMOVED|filter|' . $descr;
            unset($filter->rule[$idx]);
        }
    }
}
$logFlag = ($data['log'] === 'on');
// Create WAN-side block rules for the provided network list.
foreach ($data['block_nets'] as $net) {
    $rule = $filter->addChild('rule');
    $rule->addChild('type', 'block');
    $rule->addChild('interface', 'wan');
    $rule->addChild('direction', 'in');
    $rule->addChild('ipprotocol', 'inet');
    $rule->addChild('protocol', 'any');
    $src = $rule->addChild('source');
    if (strpos($net, '/') !== false) {
        $src->addChild('network', $net);
    } else {
        $src->addChild('address', $net);
    }
    $dst = $rule->addChild('destination');
    $dst->addChild('any');
    if ($logFlag) {
        $rule->addChild('log');
    }
    $rule->addChild('descr', ensure_prefix('Block ' . $net));
    $summary[] = 'ADDED|filter|' . (string)$rule->descr;
}
// Allow traffic from whole interfaces where requested.
foreach ($data['forward_if'] as $ifc) {
    $rule = $filter->addChild('rule');
    $rule->addChild('type', 'pass');
    $rule->addChild('interface', $ifc);
    $rule->addChild('direction', 'in');
    $rule->addChild('ipprotocol', 'inet');
    $rule->addChild('protocol', 'any');
    $src = $rule->addChild('source');
    $src->addChild('network', $ifc);
    $dst = $rule->addChild('destination');
    $dst->addChild('any');
    if ($logFlag) {
        $rule->addChild('log');
    }
    $rule->addChild('descr', ensure_prefix('Forward allow ' . $ifc));
    $summary[] = 'ADDED|filter|' . (string)$rule->descr;
}
// Allow traffic from individual IP addresses.
foreach ($data['forward_ip'] as $ip) {
    $rule = $filter->addChild('rule');
    $rule->addChild('type', 'pass');
    $rule->addChild('interface', 'wan');
    $rule->addChild('direction', 'in');
    $rule->addChild('ipprotocol', 'inet');
    $rule->addChild('protocol', 'any');
    $src = $rule->addChild('source');
    $src->addChild('address', $ip);
    $dst = $rule->addChild('destination');
    $dst->addChild('any');
    if ($logFlag) {
        $rule->addChild('log');
    }
    $rule->addChild('descr', ensure_prefix('Allow host ' . $ip));
    $summary[] = 'ADDED|filter|' . (string)$rule->descr;
}
// Add associated filter rules linked to generated port forwards.
foreach ($assocRules as $assoc) {
    $rule = $filter->addChild('rule');
    $rule->addChild('type', 'pass');
    $rule->addChild('interface', $assoc['interface']);
    $rule->addChild('direction', 'in');
    $rule->addChild('ipprotocol', 'inet');
    $rule->addChild('protocol', $assoc['proto']);
    $src = $rule->addChild('source');
    if ($assoc['src'] === 'any' || $assoc['src'] === '') {
        $src->addChild('any');
    } else {
        $src->addChild('address', $assoc['src']);
    }
    $dst = $rule->addChild('destination');
    if ($assoc['dst_ip'] !== '') {
        $dst->addChild('address', $assoc['dst_ip']);
    } else {
        $dst->addChild('any');
    }
    if ($assoc['dst_port'] !== '') {
        $dst->addChild('port', $assoc['dst_port']);
    }
    if ($logFlag) {
        $rule->addChild('log');
    }
    $rule->addChild('descr', ensure_prefix('Assoc PF ' . $assoc['label']));
    $rule->addChild('associated-rule-id', $assoc['id']);
    $summary[] = 'ADDED|filter|' . (string)$rule->descr;
}
if ($data['default_forward'] === 'deny') {
    $rule = $filter->addChild('rule');
    $rule->addChild('type', 'block');
    $rule->addChild('interface', 'wan');
    $rule->addChild('direction', 'in');
    $rule->addChild('ipprotocol', 'inet');
    $rule->addChild('protocol', 'any');
    $rule->addChild('descr', ensure_prefix('Default deny inbound'));
    $rule->addChild('source')->addChild('any');
    $rule->addChild('destination')->addChild('any');
    if ($logFlag) {
        $rule->addChild('log');
    }
    $summary[] = 'ADDED|filter|' . (string)$rule->descr;
}
$xml->asXML($xmlPath);
foreach ($summary as $line) {
    echo $line, "\n";
}
PHP
  PHP
  FIREWALL_WORK_XML="$WORK_XML" "$PHP_BIN" "$script" "$mode" "$WORK_XML"
  rc=$?
  rm -f "$script"
  return $rc
}

# firewall_run() orchestrates the lifecycle: lock, dependency checks,
# loading configuration, applying changes, and handling rollback.
firewall_run() {
  if ! create_lock; then
    return 1
  fi
  if ! check_tool pfctl "$PFCTL" || ! check_tool php "$PHP_BIN" || ! check_tool xml "$XML_BIN" || ! check_tool pfSsh.php "$PFSSH"; then
    cleanup_lock
    return 1
  fi
  if ! load_context_variables; then
    cleanup_lock
    return 1
  fi
  if [ "${FIREWALL_ENABLE}" != "on" ]; then
    log "INFO" "FIREWALL_ENABLE is off, skipping"
    cleanup_lock
    return 0
  fi
  if [ "${FIREWALL_PFCTL}" = "off" ]; then
    log "WARN" "FIREWALL_PFCTL is off, firewall module will not apply changes"
    cleanup_lock
    return 0
  fi
  if ! backup_xml; then
    cleanup_lock
    return 1
  fi
  debug "NAT input: $(prepare_nat_signature | tr '\n' ' ')"
  debug "Port forward raw: $(normalize_port_forwards)"
  debug "Forward signature: $(prepare_forward_signature | tr '\n' ' ')"
  # Ask PHP helper for the canonical desired state hash and compare with
  # the stored state to avoid unnecessary reloads.
  if ! state_string=$(run_php_helper state); then
    log "ERROR" "Failed to build desired state"
    cleanup_lock
    return 1
  fi
  [ -n "$state_string" ] || state_string="null"
  desired_hash=$(printf '%s' "$state_string" | sha256_str)
  current_hash=""
  if [ -f "$STATE_FILE" ]; then
    current_hash=$(cat "$STATE_FILE")
  fi
  if [ "$desired_hash" = "$current_hash" ]; then
    log "INFO" "No changes detected for firewall rules"
    cleanup_lock
    return 0
  fi
  # Generate the updated XML snapshot describing NAT/DNAT/filter rules.
  if ! php_output=$(run_php_helper apply); then
    log "ERROR" "PHP helper failed"
    cleanup_lock
    return 1
  fi
  # Emit log lines for additions/removals reported by the PHP helper.
  printf '%s' "$php_output" | while IFS= read -r line; do
    [ -z "$line" ] && continue
    type=${line%%|*}
    rest=${line#*|}
    category=${rest%%|*}
    descr=${rest#*|}
    case "$type" in
      REMOVED) log "INFO" "[removed] $category $descr" ;;
      ADDED) log "INFO" "[added] $category $descr" ;;
      *) log "DEBUG" "PHP: $line" ;;
    esac
  done
  # Regenerate /tmp/rules.debug using pfSense PHP helpers prior to pfctl check.
  if ! run_php_generate; then
    log "ERROR" "Failed to generate rules.debug"
    restore_xml
    cleanup_lock
    return 1
  fi
  # Validate the generated ruleset before touching the live configuration.
  if ! "$PFCTL" -nf /tmp/rules.debug >/dev/null 2>&1; then
    log "ERROR" "pfctl validation failed"
    restore_xml
    cleanup_lock
    return 1
  fi
  if ! mv "$WORK_XML" "$XML_FILE"; then
    log "ERROR" "Unable to move $WORK_XML to $XML_FILE"
    restore_xml
    cleanup_lock
    return 1
  fi
  if [ "${FIREWALL_RELOAD}" = "manual" ]; then
    log "WARN" "Manual reload requested; skipping automatic reload"
  else
    if ! "$PFSSH" playback reloadfilter >/dev/null 2>&1; then
      log "ERROR" "pfSsh reloadfilter failed"
      restore_xml
      cleanup_lock
      return 1
    fi
    if [ -x /etc/rc.reload_all ]; then
      /etc/rc.reload_all >/dev/null 2>&1 || log "WARN" "rc.reload_all returned non-zero"
    fi
  fi
  write_state "$desired_hash"
  cleanup_lock
  return 0
}

# run_php_generate() reuses pfSense PHP helpers to produce rules.debug
# from the working configuration snapshot for pfctl validation.
run_php_generate() {
  script=$(mktemp -t contextfw.gen.XXXXXX)
  cat <<'PHP' >"$script"
<?php
$work = getenv('FIREWALL_WORK_XML');
if (!$work || !file_exists($work)) {
    fwrite(STDERR, "WORK_XML missing\n");
    exit(1);
}
require_once('/etc/inc/globals.inc');
global $g;
$g['conf_path'] = dirname($work);
require_once('/etc/inc/config.inc');
global $config;
$config = parse_xml_config(basename($work), false);
if ($config === false) {
    fwrite(STDERR, "parse failed\n");
    exit(2);
}
require('/etc/rc.filter_configure_sync');
exit(0);
PHP
  PHP
  FIREWALL_WORK_XML="$WORK_XML" "$PHP_BIN" "$script" >/tmp/context-firewall.generate.log 2>&1
  rc=$?
  rm -f "$script"
  return $rc
}

# firewall_main() exists as a thin wrapper to simplify sourcing/execution
# semantics expected by ContextOnly.
firewall_main() {
  firewall_run
}

firewall_main "$@"
rc=$?
if [ "$SCRIPT_MODE" = "sourced" ]; then
  return "$rc"
else
  exit "$rc"
fi
