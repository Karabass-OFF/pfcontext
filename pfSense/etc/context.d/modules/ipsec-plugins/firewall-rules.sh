# shellcheck shell=sh 
# ============================================================
# 🧩 Firewall rules — multi-interface (WAN/LAN/OPT/...) без aliаsов
# ============================================================
log "Applying firewall rules (multi-interface, no aliases)"
/usr/local/bin/php <<'PHP'
<?php
declare(strict_types=1);

require_once('/etc/inc/config.inc');
require_once('/etc/inc/util.inc');
require_once('/etc/inc/interfaces.inc');
if (file_exists('/etc/inc/shaper.inc')) require_once('/etc/inc/shaper.inc');
require_once('/etc/inc/filter.inc');

if (!function_exists('filter_generate_dummynet_rules')) {
  function filter_generate_dummynet_rules(): string { return ''; }
}

function ctx_log(string $m): void {
  file_put_contents('/var/log/context.log', date('c')." [context-IPSEC][fw] $m\n", FILE_APPEND);
}

/* Get the interface address for destination; otherwise use (self) */
function iface_dst_ip_or_self(string $iface): array {
  $ip = get_interface_ip($iface) ?: '';
  if ($ip !== '') return ['address' => $ip];
  return ['address' => '(self)'];
}

global $config;

/* Ensure the rules array exists */
if (!isset($config['filter']['rule']) || !is_array($config['filter']['rule'])) {
  $config['filter']['rule'] = [];
}

/* Find rule by iface+descr */
$find_rule = function(string $iface, string $descr): ?int {
  global $config;
  foreach ($config['filter']['rule'] as $i => $r) {
    if (($r['interface'] ?? '') === $iface && ($r['descr'] ?? '') === $descr) return $i;
  }
  return null;
};

/* --- 1) IKE / NAT-T / ESP on Phase1 interfaces --- */
foreach (($config['ipsec']['phase1'] ?? []) as $p1) {
  $iface  = $p1['interface'] ?? 'wan';
  $remote = trim((string)($p1['remote-gateway'] ?? ''));
  if ($remote === '') continue;

  $dst = iface_dst_ip_or_self($iface);
  if ($dst['address'] === '(self)') {
    ctx_log("NOTICE: $iface has no IPv4 yet; using (self) to avoid alias issues");
  } else {
    ctx_log("Using concrete IP {$dst['address']} as destination on $iface");
  }

  $defs = [
    ['proto' => 'udp', 'port' => '500',  'descr' => "[context] IKE (500) from $remote"],
    ['proto' => 'udp', 'port' => '4500', 'descr' => "[context] NAT-T (4500) from $remote"],
    ['proto' => 'esp', 'port' => '',     'descr' => "[context] ESP from $remote"],
  ];

  foreach ($defs as $r) {
    $dst_rule = $dst;
    if ($r['port'] !== '') $dst_rule['port'] = $r['port'];

    $idx = $find_rule($iface, $r['descr']);
    if ($idx !== null) {
      $config['filter']['rule'][$idx] = array_merge($config['filter']['rule'][$idx], [
        'type'        => 'pass',
        'ipprotocol'  => 'inet',
        'protocol'    => $r['proto'],
        'source'      => ['address' => $remote],
        'destination' => $dst_rule,
        'updated'     => date('c'),
      ]);
      unset($config['filter']['rule'][$idx]['disabled']);
      ctx_log("Updated rule on $iface: {$r['descr']}");
    } else {
      $config['filter']['rule'][] = [
        'type'        => 'pass',
        'interface'   => $iface,
        'ipprotocol'  => 'inet',
        'protocol'    => $r['proto'],
        'source'      => ['address' => $remote],
        'destination' => $dst_rule,
        'descr'       => $r['descr'],
        'created'     => date('c'),
        'updated'     => date('c'),
      ];
      ctx_log("Added rule on $iface: {$r['descr']}");
    }
  }
}

/* --- 2) Universal "allow-all" rule on the IPsec interface --- */

// IPsec in pfSense is the virtual interface enc0 (unless a VTI is assigned)
$ipsec_if = array_key_exists('ipsec', $config['interfaces'] ?? []) ? 'ipsec' : 'enc0';

$descr_v4 = '[context] IPsec allow all traffic (IPv4)';
$descr_v6 = '[context] IPsec allow all traffic (IPv6)';

/* IPv4 */
$idx_v4 = $find_rule($ipsec_if, $descr_v4);
$rule_v4 = [
  'type'        => 'pass',
  'interface'   => $ipsec_if,
  'ipprotocol'  => 'inet',
  'protocol'    => 'any',
  'source'      => ['any' => ''],
  'destination' => ['any' => ''],
  'descr'       => $descr_v4,
];

if ($idx_v4 !== null) {
  $config['filter']['rule'][$idx_v4] = array_merge($config['filter']['rule'][$idx_v4], $rule_v4, [
    'updated' => date('c'),
  ]);
  unset($config['filter']['rule'][$idx_v4]['disabled']);
  ctx_log("Updated IPv4 allow-all rule on {$ipsec_if}");
} else {
  $rule_v4['created'] = date('c');
  $rule_v4['updated'] = date('c');
  $config['filter']['rule'][] = $rule_v4;
  ctx_log("Added IPv4 allow-all rule on {$ipsec_if}");
}

/* IPv6 */
$idx_v6 = $find_rule($ipsec_if, $descr_v6);
$rule_v6 = [
  'type'        => 'pass',
  'interface'   => $ipsec_if,
  'ipprotocol'  => 'inet6',
  'protocol'    => 'any',
  'source'      => ['any' => ''],
  'destination' => ['any' => ''],
  'descr'       => $descr_v6,
];

if ($idx_v6 !== null) {
  $config['filter']['rule'][$idx_v6] = array_merge($config['filter']['rule'][$idx_v6], $rule_v6, [
    'updated' => date('c'),
  ]);
  unset($config['filter']['rule'][$idx_v6]['disabled']);
  ctx_log("Updated IPv6 allow-all rule on {$ipsec_if}");
} else {
  $rule_v6['created'] = date('c');
  $rule_v6['updated'] = date('c');
  $config['filter']['rule'][] = $rule_v6;
  ctx_log("Added IPv6 allow-all rule on {$ipsec_if}");
}


/* --- 3) Save and apply --- */
write_config('[context-IPSEC] Applied firewall rules (no-alias)', false);
try {
  filter_configure_sync();
  ctx_log('Firewall reloaded successfully');
} catch (Throwable $e) {
  ctx_log('filter_configure_sync() failed: '.$e->getMessage().'; sending filter reload');
  if (function_exists('send_event')) send_event('filter reload');
}
PHP