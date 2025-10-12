#!/bin/sh
# Context firewall automation module for pfSense

set -eu

BASEDIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
# shellcheck source=functions.sh
. "$BASEDIR/functions.sh"
# shellcheck source=vars.sh
. "$BASEDIR/vars.sh"

log "=== firewall module start ==="

# Dependency checks
missing=false
for dep in pfctl /usr/local/bin/php pfSsh.php; do
    if ! require_command "$dep"; then
        missing=true
    fi
done
if [ "$missing" = true ]; then
    log "Dependencies missing, aborting"
    exit 1
fi

if [ "$FIREWALL_ENABLE" != "on" ]; then
    log "FIREWALL_ENABLE is not 'on' — skipping firewall provisioning"
    exit 0
fi

if [ "$FIREWALL_PFCTL" = "off" ]; then
    log "FIREWALL_PFCTL=off — firewall configuration not applied"
    exit 0
fi

log "Outbound NAT interface: $FIREWALL_NAT_OUT_IF"
log "Forward default policy: $FIREWALL_DEFAULT_FORWARD"
log "Port-forward rules requested: $(normalize_space "$FW_PORT_FORWARDS")"

export FW_APPLY_NOW="$([ "$FIREWALL_RELOAD" = "auto" ] && echo on || echo off)"

run_php_inline <<'PHP'
<?php
require_once('/etc/inc/globals.inc');
require_once('/etc/inc/config.inc');
require_once('/etc/inc/filter.inc');
require_once('/etc/inc/util.inc');

$logFile = getenv('FIREWALL_LOG_FILE') ?: '/var/log/context-firewall.log';
$logEnabled = getenv('FIREWALL_LOG') === 'on';
function fw_log($msg) {
    global $logFile, $logEnabled;
    if (!$logEnabled) {
        return;
    }
    $ts = date('Y-m-d H:i:s');
    file_put_contents($logFile, sprintf("%s [context-firewall] %s\n", $ts, $msg), FILE_APPEND | LOCK_EX);
}

function explode_list($envName) {
    $value = trim((string)getenv($envName));
    if ($value === '') {
        return [];
    }
    $items = preg_split('/\s+/', $value, -1, PREG_SPLIT_NO_EMPTY);
    return array_values(array_unique($items));
}

$natOutIf = trim((string)getenv('FIREWALL_NAT_OUT_IF')) ?: 'wan';
$natNetworks = explode_list('FW_NAT_NETS');
$natHosts = explode_list('FW_NAT_HOSTS');
$allowNets = explode_list('FW_ALLOW_NETS');
$blockNets = explode_list('FW_BLOCK_NETS');
$forwardIfs = explode_list('FW_FORWARD_ALLOW');
$portForwards = explode_list('FW_PORT_FORWARDS');
$defaultForward = strtolower((string)getenv('FIREWALL_DEFAULT_FORWARD')) === 'allow' ? 'allow' : 'deny';

if (!isset($config['aliases'])) {
    $config['aliases'] = [];
}
if (!isset($config['aliases']['alias'])) {
    $config['aliases']['alias'] = [];
}

function update_alias($name, array $networks, $descr) {
    global $config;
    // Drop existing alias with same name
    $newAliases = [];
    foreach ($config['aliases']['alias'] as $alias) {
        if (isset($alias['name']) && $alias['name'] === $name) {
            continue;
        }
        $newAliases[] = $alias;
    }
    $config['aliases']['alias'] = $newAliases;
    if (empty($networks)) {
        return;
    }
    $config['aliases']['alias'][] = [
        'name' => $name,
        'type' => 'network',
        'descr' => $descr,
        'address' => implode('\n', $networks),
        'detail' => implode('\n', array_fill(0, count($networks), 'context-firewall')),
    ];
}

update_alias('CTX_ALLOW_NETS', $allowNets, 'Context firewall allow list');
update_alias('CTX_BLOCK_NETS', $blockNets, 'Context firewall block list');
fw_log('Aliases synchronized');

if (!isset($config['nat'])) {
    $config['nat'] = [];
}
if (!isset($config['nat']['outbound'])) {
    $config['nat']['outbound'] = [];
}
if (!isset($config['nat']['outbound']['rule']) || !is_array($config['nat']['outbound']['rule'])) {
    $config['nat']['outbound']['rule'] = [];
}
$config['nat']['outbound']['mode'] = 'advanced';

$existingOutbound = [];
foreach ($config['nat']['outbound']['rule'] as $rule) {
    $descr = isset($rule['descr']) ? $rule['descr'] : '';
    if (strpos($descr, 'Context NAT:') === 0) {
        continue;
    }
    $existingOutbound[] = $rule;
}
$config['nat']['outbound']['rule'] = $existingOutbound;

$createdMeta = [
    'time' => date('Y-m-d H:i:s'),
    'username' => 'context-firewall',
];

foreach ($natNetworks as $network) {
    $config['nat']['outbound']['rule'][] = [
        'interface' => $natOutIf,
        'protocol' => 'any',
        'source' => ['network' => $network],
        'destination' => ['any' => ''],
        'target' => '',
        'natport' => '',
        'descr' => 'Context NAT: ' . $network,
        'staticnatport' => 'auto',
        'created' => $createdMeta,
        'updated' => $createdMeta,
    ];
}

foreach ($natHosts as $host) {
    $config['nat']['outbound']['rule'][] = [
        'interface' => $natOutIf,
        'protocol' => 'any',
        'source' => ['address' => $host],
        'destination' => ['any' => ''],
        'target' => '',
        'natport' => '',
        'descr' => 'Context NAT host: ' . $host,
        'staticnatport' => 'auto',
        'created' => $createdMeta,
        'updated' => $createdMeta,
    ];
}

if (!isset($config['nat']['rule']) || !is_array($config['nat']['rule'])) {
    $config['nat']['rule'] = [];
}
$newPortRules = [];
foreach ($config['nat']['rule'] as $rule) {
    $descr = isset($rule['descr']) ? $rule['descr'] : '';
    if (strpos($descr, 'Context DNAT:') === 0) {
        continue;
    }
    $newPortRules[] = $rule;
}
$config['nat']['rule'] = $newPortRules;

foreach ($portForwards as $entry) {
    $parts = explode(':', $entry);
    if (count($parts) !== 5) {
        fw_log('Skipping malformed port forward entry: ' . $entry);
        continue;
    }
    list($iface, $proto, $extPort, $intIp, $intPort) = $parts;
    $ruleDescr = sprintf('Context DNAT: %s %s %s->%s:%s', $iface, strtolower($proto), $extPort, $intIp, $intPort);
    $config['nat']['rule'][] = [
        'interface' => $iface,
        'protocol' => strtolower($proto),
        'ipprotocol' => 'inet',
        'descr' => $ruleDescr,
        'destination' => [
            'network' => 'wanip',
            'port' => $extPort,
        ],
        'target' => $intIp,
        'local-port' => $intPort,
        'associated-rule-id' => 'pass',
        'created' => $createdMeta,
        'updated' => $createdMeta,
    ];
}

if (!isset($config['filter'])) {
    $config['filter'] = [];
}
if (!isset($config['filter']['rule']) || !is_array($config['filter']['rule'])) {
    $config['filter']['rule'] = [];
}
$preservedFilter = [];
foreach ($config['filter']['rule'] as $rule) {
    $descr = isset($rule['descr']) ? $rule['descr'] : '';
    if (strpos($descr, 'Context FW:') === 0) {
        continue;
    }
    $preservedFilter[] = $rule;
}
$config['filter']['rule'] = $preservedFilter;

$interfacesToProtect = array_values(array_unique($forwardIfs));

foreach ($interfacesToProtect as $iface) {
    foreach ($interfacesToProtect as $target) {
        if ($iface === $target) {
            continue;
        }
        $config['filter']['rule'][] = [
            'type' => 'pass',
            'interface' => $iface,
            'ipprotocol' => 'inet',
            'protocol' => 'any',
            'source' => ['network' => $iface],
            'destination' => ['network' => $target],
            'descr' => sprintf('Context FW: allow %s->%s', $iface, $target),
        ];
    }
}

if (!empty($blockNets)) {
    $config['filter']['rule'][] = [
        'type' => 'block',
        'interface' => 'wan',
        'ipprotocol' => 'inet',
        'protocol' => 'any',
        'source' => ['address' => 'CTX_BLOCK_NETS'],
        'destination' => ['any' => ''],
        'descr' => 'Context FW: block alias CTX_BLOCK_NETS',
    ];
}

if ($defaultForward === 'deny') {
    foreach ($interfacesToProtect as $iface) {
        $config['filter']['rule'][] = [
            'type' => 'block',
            'interface' => $iface,
            'ipprotocol' => 'inet',
            'protocol' => 'any',
            'source' => ['network' => $iface],
            'destination' => ['any' => ''],
            'descr' => sprintf('Context FW: default deny %s', $iface),
        ];
    }
}

write_config('[context] firewall automation update');
fw_log('Configuration updated');

$apply = getenv('FW_APPLY_NOW') === 'on';
if ($apply) {
    $retval = filter_configure();
    fw_log('filter_configure() returned ' . (string)$retval);
}
PHP
PHP_STATUS=$?
if [ "$PHP_STATUS" -ne 0 ]; then
    log "PHP apply failed with status $PHP_STATUS"
    exit "$PHP_STATUS"
fi

if [ "$FIREWALL_RELOAD" = "auto" ]; then
    if [ -f /tmp/rules.debug ]; then
        if pfctl -nf /tmp/rules.debug >>"$FIREWALL_LOG_FILE" 2>&1; then
            pfctl -f /tmp/rules.debug >>"$FIREWALL_LOG_FILE" 2>&1
            log "pfctl rules applied"
        else
            log "pfctl syntax check failed; rules not applied"
        fi
    else
        log "/tmp/rules.debug missing, skipping pfctl apply"
    fi
else
    log "FIREWALL_RELOAD=manual — configuration saved without applying"
fi

log "=== firewall module complete ==="
