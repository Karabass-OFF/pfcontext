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

/* Получить адрес интерфейса для destination; иначе (self) */
function iface_dst_ip_or_self(string $iface): array {
  $ip = get_interface_ip($iface) ?: '';
  if ($ip !== '') return ['address' => $ip];
  return ['address' => '(self)'];
}

global $config;

/* Гарантируем массив правил */
if (!isset($config['filter']['rule']) || !is_array($config['filter']['rule'])) {
  $config['filter']['rule'] = [];
}

/* Поиск правила по iface+descr */
$find_rule = function(string $iface, string $descr): ?int {
  global $config;
  foreach ($config['filter']['rule'] as $i => $r) {
    if (($r['interface'] ?? '') === $iface && ($r['descr'] ?? '') === $descr) return $i;
  }
  return null;
};

/* --- 1) IKE/NAT-T/ESP на интерфейсах Phase1 --- */
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

/* --- 2) Разрешающие правила на IPsec для сетей Phase2 --- */
foreach (($config['ipsec']['phase2'] ?? []) as $p2) {
  $lid = $p2['localid']  ?? [];
  $rid = $p2['remoteid'] ?? [];
  if (($lid['type'] ?? '') !== 'network' || ($rid['type'] ?? '') !== 'network') continue;

  $la = trim((string)($lid['address'] ?? ''));
  $lb = (string)($lid['netbits'] ?? '');
  $ra = trim((string)($rid['address'] ?? ''));
  $rb = (string)($rid['netbits'] ?? '');
  if ($la === '' || $lb === '' || $ra === '' || $rb === '') continue;

  $descr = "[context] IPsec {$ra}/{$rb} → {$la}/{$lb}";
  $src = [
    'type'    => 'network',   // или 'address'
    'network' => "{$ra}/{$rb}"
  ];
  $dst = [
    'type'    => 'network',   // или 'address'
    'network' => "{$la}/{$lb}"
];

  $idx = $find_rule('ipsec', $descr);
  if ($idx !== null) {
    $config['filter']['rule'][$idx] = array_merge($config['filter']['rule'][$idx], [
      'type'           => 'pass',
      'interface'      => 'ipsec',
      'ipprotocol'     => 'inet',
      'protocol'       => 'any',
      'source'         => $src,
      'destination'    => $dst,
      'apply_to_ipsec' => 'yes',
      'updated'        => date('c'),
    ]);
    unset($config['filter']['rule'][$idx]['disabled']);
    ctx_log("Updated IPsec rule: $descr");
  } else {
    $config['filter']['rule'][] = [
      'type'           => 'pass',
      'interface'      => 'ipsec',
      'ipprotocol'     => 'inet',
      'protocol'       => 'any',
      'source'         => $src,
      'destination'    => $dst,
      'apply_to_ipsec' => 'yes',
      'descr'          => $descr,
      'created'        => date('c'),
      'updated'        => date('c'),
    ];
    ctx_log("Added IPsec rule: $descr");
  }
}

/* --- 3) Сохранить и применить --- */
write_config('[context-IPSEC] Applied firewall rules (no-alias)', false);
try {
  filter_configure_sync();
  ctx_log('Firewall reloaded successfully');
} catch (Throwable $e) {
  ctx_log('filter_configure_sync() failed: '.$e->getMessage().'; sending filter reload');
  if (function_exists('send_event')) send_event('filter reload');
}
PHP