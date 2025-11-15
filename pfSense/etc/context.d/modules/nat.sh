#!/bin/sh
# =====================================================================
#  pfContext Module — NAT (Outbound)
#  Version: v2.2
#  Modes: automatic | hybrid | manual(advanced) | disabled
# =====================================================================

: "${NAT_ENABLE:=YES}"
: "${NAT_IF:=wan}"        # outbound interface
: "${FW_IF:=opt1}"        # internal interface (source network for NAT)
: "${NAT_MODE:=manual}"   # recommended use manual or disabled, tested hybrid and automatic 

LOG="/var/log/context.log"

log() {
  printf '%s [context-NAT:nat.sh] %s\n' "$(date)" "$*" >> "$LOG"
}

# =====================================================================
# Helper: get interface NETWORK/CIDR (not host IP) 
# =====================================================================
iface_info() {
  /usr/local/bin/php -r "
    require_once('/etc/inc/interfaces.inc');
    require_once('/etc/inc/util.inc');

    \$if = '$1';
    \$real = get_real_interface(\$if);
    if (!\$real) { echo \"ERR:no_if\"; exit; }

    \$ip   = get_interface_ip(\$if);
    \$mask = get_interface_subnet(\$if);   // CIDR: 24, 16 ...

    if (!\$ip || !\$mask) { echo \"ERR:no_ip\"; exit; }

    // network = e.g. 10.121.14.0
    \$net = gen_subnet(\$ip, \$mask);

    echo \"\$net/\$mask\";
  "
}

# =====================================================================
# 1. Set NAT mode (only mode, без правил)
# =====================================================================
nat_set_mode() {
  log "Setting NAT mode to $NAT_MODE on interface $NAT_IF"

  # маппинг режимов pfSense
  PFS_MODE="$NAT_MODE"
  case "$NAT_MODE" in
    manual)   PFS_MODE="advanced" ;;
    disabled) PFS_MODE="disabled" ;;
    automatic|hybrid) : ;;
    *)        PFS_MODE="automatic" ;;
  esac

  /usr/local/bin/php -r "
    require_once('/etc/inc/config.inc');
    require_once('/etc/inc/filter.inc');
    global \$config;

    if (!isset(\$config['nat']) || !is_array(\$config['nat'])) {
        \$config['nat'] = [];
    }
    if (!isset(\$config['nat']['outbound']) || !is_array(\$config['nat']['outbound'])) {
        \$config['nat']['outbound'] = [];
    }

    \$mode = '$PFS_MODE';
    \$config['nat']['outbound']['mode'] = \$mode;

    // Если режим automatic — чистим кастомные правила, как делает GUI
    if (\$mode === 'automatic') {
        unset(\$config['nat']['outbound']['rule']);
    }

    write_config('context: NAT mode updated');
    filter_configure();
  " 2>>"$LOG"
}

# =====================================================================
# 2. Generate outbound NAT rule (для hybrid/advanced)
# =====================================================================
nat_generate_rule() {
  CIDR=$(iface_info "$FW_IF")

  if echo "$CIDR" | grep -q "^ERR"; then
    log "Cannot generate NAT rule — interface $FW_IF has no IP/network"
    return
  fi

  log "Generating outbound NAT rule: $CIDR → $NAT_IF"

  /usr/local/bin/php -r "
    require_once('/etc/inc/config.inc');
    require_once('/etc/inc/filter.inc');
    global \$config;

    \$if_n = '$NAT_IF';
    \$cidr = '$CIDR';

    if (!isset(\$config['nat']) || !is_array(\$config['nat'])) {
        \$config['nat'] = [];
    }
    if (!isset(\$config['nat']['outbound']) || !is_array(\$config['nat']['outbound'])) {
        \$config['nat']['outbound'] = [];
    }
    if (!isset(\$config['nat']['outbound']['rule']) || !is_array(\$config['nat']['outbound']['rule'])) {
        \$config['nat']['outbound']['rule'] = [];
    }

    // Duplicate protection
    foreach (\$config['nat']['outbound']['rule'] as \$r) {
        if (
            (\$r['source']['network'] ?? '') === \$cidr &&
            (\$r['interface'] ?? '') === \$if_n
        ) {
            // правило уже есть
            exit;
        }
    }

    \$config['nat']['outbound']['rule'][] = [
        'interface'   => \$if_n,
        'source'      => ['network' => \$cidr],
        'destination' => ['any' => ''],
        'descr'       => 'context-auto-outbound'
    ];

    write_config('context: outbound NAT rule added');
    filter_configure();
  " 2>>"$LOG"
}

# =====================================================================
# 3. Firewall rule: allow-any NOT <IF_IP>
# =====================================================================
fw_allow_any() {
  log "Adding firewall allow-any rule on $FW_IF"

  /usr/local/bin/php -r "
    require_once('/etc/inc/config.inc');
    require_once('/etc/inc/filter.inc');
    require_once('/etc/inc/interfaces.inc');
    global \$config;

    \$if = '$FW_IF';
    \$real = get_real_interface(\$if);
    if (!\$real) exit;

    \$ip = get_interface_ip(\$if);
    if (!\$ip) exit;

    if (!isset(\$config['filter']) || !is_array(\$config['filter'])) {
        \$config['filter'] = [];
    }
    if (!isset(\$config['filter']['rule']) || !is_array(\$config['filter']['rule'])) {
        \$config['filter']['rule'] = [];
    }

    // Duplicate check
    foreach (\$config['filter']['rule'] as \$r) {
        if (
            (\$r['interface'] ?? '') === \$if &&
            (\$r['protocol'] ?? '') === 'any' &&
            isset(\$r['destination']['not']) &&
            (\$r['destination']['address'] ?? '') === \$ip
        ) {
            exit;
        }
    }

    \$config['filter']['rule'][] = [
        'type'      => 'pass',
        'interface' => \$if,
        'protocol'  => 'any',
        'source'    => ['any' => ''],
        'destination' => [
            'not'     => '',
            'address' => \$ip
        ],
        'descr'     => 'context-auto-allow-any'
    ];

    write_config('context: auto FW rule added');
    filter_configure();
  " 2>>"$LOG"
}

# =====================================================================
# Main
# =====================================================================

log "NAT module start — mode=$NAT_MODE NAT_IF=$NAT_IF FW_IF=$FW_IF"

if [ "$NAT_ENABLE" != "YES" ]; then
  log "NAT disabled — exit"
  return 0
fi

nat_set_mode

case "$NAT_MODE" in
  hybrid|manual)
    nat_generate_rule
    ;;
  automatic)
    log "Mode automatic — pfSense manages NAT itself"
    ;;
  disabled)
    log "Mode disabled — no outbound NAT rules"
    ;;
esac

fw_allow_any

log "NAT module finished successfully"
exit 0
