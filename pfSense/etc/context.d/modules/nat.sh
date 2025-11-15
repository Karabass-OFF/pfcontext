#!/bin/sh
# =====================================================================
#  pfContext Module — NAT (Outbound)
#  Version: v1.2 (simplified)
#  Purpose: sets outbound NAT mode and firewall rules.
# =====================================================================

: "${NAT_ENABLE:=YES}"  # enable NAT module
: "${NAT_IF:=wan}"      # outbound NAT interface
: "${FW_IF:=opt1}"      # firewall allow-all
: "${NAT_MODE:=hybrid}" # outbound NAT mode: automatic, hybrid, manual
LOG="/var/log/context.log"

log() {
  printf '%s [context-NAT:nat.sh] %s\n' "$(date)" "$*" >> "$LOG"
}

# =====================================================================
# 1.  NAT Mode Handling
# =====================================================================

nat_apply() {
 log "Starting NAT module"

  [ "$NAT_ENABLE" != "YES" ] && {
    log "NAT disabled — exiting"
    return 0
  }

  #  Validate NAT interface
  IF_REAL=$(/usr/local/bin/php -r "
    require_once('/etc/inc/interfaces.inc');
    \$if = get_real_interface('$NAT_IF');
    if (!empty(\$if)) echo \$if;
  " 2>/dev/null)

  if [ -z "$IF_REAL" ]; then
    log "ERROR: interface '$NAT_IF' does not exist"
    return 1
  fi

  log "Using outbound interface: $NAT_IF ($IF_REAL)"
  log "Requested NAT mode: $NAT_MODE"

  /usr/local/bin/php -r "
    require_once('/etc/inc/config.inc');
    require_once('/etc/inc/filter.inc');
    global \$config;

    if (!is_array(\$config['nat']))             \$config['nat'] = [];
    if (!is_array(\$config['nat']['outbound'])) \$config['nat']['outbound'] = [];

    // Set outbound NAT mode
    \$config['nat']['outbound']['mode'] = '$NAT_MODE';

    write_config('context: outbound NAT mode updated');
    filter_configure();
  " 2>>"$LOG"

  # Log final mode
  /usr/local/bin/php -r "
    require_once('/etc/inc/config.inc');
    global \$config;
    \$mode = \$config['nat']['outbound']['mode'] ?? 'undefined';
    echo '[' . date('Y-m-d H:i:s') . '][context-NAT:nat.sh] Итоговый режим: ' . \$mode . \"\n\";
  " >>"$LOG" 2>/dev/null

  log "NAT module finished"
}

# =====================================================================
# 2. Firewall Rule: allow-any + NOT interface IP
# =====================================================================

fw_allow_any() {
  log "Creating allow-any rule on FW_IF: $FW_IF"

  /usr/local/bin/php -r "
    require_once('/etc/inc/config.inc');
    require_once('/etc/inc/filter.inc');
    require_once('/etc/inc/interfaces.inc');
    global \$config;

    \$if = '$FW_IF';

    // Validate interface
    \$real = get_real_interface(\$if);
    if (empty(\$real)) {
        echo \"FW_IF interface does not exist\n\";
        exit;
    }

    // Get IPv4 address
    \$ip = get_interface_ip(\$if);
    if (empty(\$ip)) {
        echo \"FW_IF has no IPv4 address\n\";
        exit;
    }

    if (!is_array(\$config['filter'])) \$config['filter'] = [];
    if (!is_array(\$config['filter']['rule'])) \$config['filter']['rule'] = [];

    // Check if rule already exists
    foreach (\$config['filter']['rule'] as \$rule) {
        if (
            (\$rule['interface'] ?? '') === \$if &&
            (\$rule['protocol'] ?? '') === 'any' &&
            (\$rule['type'] ?? '') === 'pass' &&
            isset(\$rule['destination']['not']) &&
            (\$rule['destination']['address'] ?? '') === \$ip
        ) {
            echo \"Rule already exists\n\";
            exit;
        }
    }

    // Create new rule: PASS ANY → NOT <interface IP>
    \$config['filter']['rule'][] = [
        'type'        => 'pass',
        'interface'   => \$if,
        'protocol'    => 'any',
        'source'      => ['any' => ''],

        'destination' => [
            'not'     => '',
            'address' => \$ip   
        ],

        'descr'       => 'context-auto-allow-any'
    ];

    echo \"Added allow-any rule on \$if (not \$ip)\";
    write_config('context: add allow-any rule (not interface IP)');
    filter_configure();
  " 2>>"$LOG"
}

nat_apply
fw_allow_any