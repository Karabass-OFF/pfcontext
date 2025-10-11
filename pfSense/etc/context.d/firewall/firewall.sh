#!/bin/sh
# Context firewall orchestrator for pfSense

PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin

BASE_DIR=$(dirname "$0")
# shellcheck source=functions.sh
. "$BASE_DIR/functions.sh"
# shellcheck source=vars.sh
. "$BASE_DIR/vars.sh"

FIREWALL_LOG=${FIREWALL_LOG:-on}
init_logging

if ! load_context_vars; then
    log_event error "context.sh not found — skipping firewall configuration"
    exit 0
fi

# Reload logging configuration according to context
init_logging
log_event apply "context firewall module start (context: ${CONTEXT_SOURCE})"

missing_cmd=""
for cmd in pfctl php pfSsh.php; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        missing_cmd="$missing_cmd $cmd"
    fi
done
if [ -n "$missing_cmd" ]; then
    log_event error "missing required commands:$missing_cmd"
    exit 1
fi

flush_anchor() {
    pfctl -a "$ANCHOR_NAME" -F rules >/dev/null 2>&1
}

if [ "${FIREWALL_ENABLE}" != "on" ]; then
    flush_anchor
    rm -f "$STATE_FILE" "$RULE_FILE"
    log_event apply "module disabled via FIREWALL_ENABLE=${FIREWALL_ENABLE}"
    exit 0
fi

if [ "${FIREWALL_PFCTL}" != "on" ]; then
    log_event apply "FIREWALL_PFCTL=${FIREWALL_PFCTL} — rules not applied"
    exit 0
fi

ensure_state_dir || {
    log_event error "unable to create state directory for $STATE_FILE"
    exit 1
}

# Load previous state
PREV_FIREWALL_NAT_OUT_IF=""
PREV_FIREWALL_NAT_NETS=""
PREV_FIREWALL_NAT_HOSTS=""
PREV_FIREWALL_NAT_ALLOW_NETS=""
PREV_FIREWALL_BLOCK_NETS=""
PREV_FIREWALL_PORT_FORWARD_LIST=""
PREV_FIREWALL_FORWARD_ALLOW=""
PREV_FIREWALL_DEFAULT_FORWARD=""
PREV_CONTEXT_SOURCE=""

if [ -f "$STATE_FILE" ]; then
    # shellcheck disable=SC1090
    . "$STATE_FILE"
fi

changed=0

compare_list() {
    old_list=$(normalize_spaces "$1")
    new_list=$(normalize_spaces "$2")
    label=$3

    for item in $old_list; do
        if ! list_contains "$item" "$new_list"; then
            log_event remove "$label removed: $item"
            changed=1
        fi
    done
    for item in $new_list; do
        if ! list_contains "$item" "$old_list"; then
            log_event apply "$label added: $item"
            changed=1
        fi
    done
}

if [ "${PREV_FIREWALL_NAT_OUT_IF}" != "${FIREWALL_NAT_OUT_IF}" ]; then
    if [ -n "${PREV_FIREWALL_NAT_OUT_IF}" ]; then
        log_event update "NAT interface changed: ${PREV_FIREWALL_NAT_OUT_IF} -> ${FIREWALL_NAT_OUT_IF}"
    else
        log_event apply "NAT interface set: ${FIREWALL_NAT_OUT_IF}"
    fi
    changed=1
fi

compare_list "${PREV_FIREWALL_NAT_NETS}" "${FIREWALL_NAT_NETS}" "nat-network"
compare_list "${PREV_FIREWALL_NAT_HOSTS}" "${FIREWALL_NAT_HOSTS}" "nat-host"
compare_list "${PREV_FIREWALL_NAT_ALLOW_NETS}" "${FIREWALL_NAT_ALLOW_NETS}" "nat-allow"
compare_list "${PREV_FIREWALL_BLOCK_NETS}" "${FIREWALL_BLOCK_NETS}" "block-net"
compare_list "${PREV_FIREWALL_PORT_FORWARD_LIST}" "${FIREWALL_PORT_FORWARD_LIST}" "dnat"

forward_current=$(echo "${FIREWALL_FORWARD_ALLOW}" | tr ',' ' ')
forward_current=$(normalize_spaces "$forward_current")
forward_previous=$(echo "${PREV_FIREWALL_FORWARD_ALLOW}" | tr ',' ' ')
forward_previous=$(normalize_spaces "$forward_previous")
compare_list "$forward_previous" "$forward_current" "forward-iface"

if [ "${PREV_FIREWALL_DEFAULT_FORWARD}" != "${FIREWALL_DEFAULT_FORWARD}" ]; then
    if [ -n "${PREV_FIREWALL_DEFAULT_FORWARD}" ]; then
        log_event update "default forward changed: ${PREV_FIREWALL_DEFAULT_FORWARD} -> ${FIREWALL_DEFAULT_FORWARD}"
    else
        log_event apply "default forward policy: ${FIREWALL_DEFAULT_FORWARD}"
    fi
    changed=1
fi

if [ "$changed" -eq 0 ] && [ "$CONTEXT_SOURCE" = "${PREV_CONTEXT_SOURCE}" ]; then
    log_event apply "no firewall changes detected"
    exit 0
fi

reload_mode=$(echo "${FIREWALL_RELOAD}" | tr 'A-Z' 'a-z')
if [ "$reload_mode" = "manual" ]; then
    log_event update "changes detected but FIREWALL_RELOAD=manual — waiting for manual reload"
    exit 0
fi

if [ -z "$FIREWALL_NAT_OUT_IF" ] && [ -n "$FIREWALL_NAT_NETS$FIREWALL_NAT_HOSTS" ]; then
    log_event error "NAT sources defined but FIREWALL_NAT_OUT_IF is empty"
    exit 1
fi

workdir=$(mk_workdir)
if [ -z "$workdir" ] || [ ! -d "$workdir" ]; then
    log_event error "unable to create working directory"
    exit 1
fi

cleanup() {
    rm -rf "$workdir"
}
trap cleanup EXIT INT TERM

nat_sources=$(normalize_spaces "${FIREWALL_NAT_NETS} ${FIREWALL_NAT_HOSTS}")

# Build table definitions
TABLE_DEFS="# context firewall tables"
if [ -n "$FIREWALL_NAT_ALLOW_NETS" ]; then
    TABLE_DEFS="$TABLE_DEFS\ntable <context_nat_allow> persist { ${FIREWALL_NAT_ALLOW_NETS} }"
else
    TABLE_DEFS="$TABLE_DEFS\ntable <context_nat_allow> persist"
fi

if [ -n "$FIREWALL_BLOCK_NETS" ]; then
    TABLE_DEFS="$TABLE_DEFS\ntable <context_block> persist { ${FIREWALL_BLOCK_NETS} }"
else
    TABLE_DEFS="$TABLE_DEFS\ntable <context_block> persist"
fi

if [ -n "$nat_sources" ]; then
    TABLE_DEFS="$TABLE_DEFS\ntable <context_nat_sources> persist { ${nat_sources} }"
else
    TABLE_DEFS="$TABLE_DEFS\ntable <context_nat_sources> persist"
fi

BASE_RULES="# context firewall anchor\nset skip on lo0\n${TABLE_DEFS}"

RULE_INDEX=0
RULE_FILES=""

add_rule_group() {
    desc=$1
    rules=$2
    RULE_INDEX=$((RULE_INDEX + 1))
    rule_file="$workdir/rule_${RULE_INDEX}.rules"
    desc_file="$workdir/rule_${RULE_INDEX}.desc"
    printf '%s\n' "$rules" >"$rule_file"
    printf '%s\n' "$desc" >"$desc_file"
    RULE_FILES="$RULE_FILES $rule_file"
}

if [ -n "$FIREWALL_BLOCK_NETS" ]; then
    add_rule_group "block-nets" "block in quick from <context_block> to any\nblock out quick to <context_block>"
fi

if [ -n "$FIREWALL_NAT_OUT_IF" ] && [ -n "$nat_sources" ]; then
    add_rule_group "outbound-nat" "nat on ${FIREWALL_NAT_OUT_IF} from <context_nat_sources> to any -> (${FIREWALL_NAT_OUT_IF})\npass out quick on ${FIREWALL_NAT_OUT_IF} from <context_nat_sources> to any keep state"
fi

if [ -n "$FIREWALL_NAT_OUT_IF" ] && [ -n "$FIREWALL_NAT_ALLOW_NETS" ]; then
    add_rule_group "nat-allow" "pass out quick on ${FIREWALL_NAT_OUT_IF} from <context_nat_allow> to any keep state"
fi

for entry in $FIREWALL_PORT_FORWARD_LIST; do
    iface=$(printf '%s' "$entry" | cut -d: -f1)
    proto=$(printf '%s' "$entry" | cut -d: -f2)
    ext_port=$(printf '%s' "$entry" | cut -d: -f3)
    internal_ip=$(printf '%s' "$entry" | cut -d: -f4)
    internal_port=$(printf '%s' "$entry" | cut -d: -f5)
    if [ -n "$iface" ] && [ -n "$proto" ] && [ -n "$ext_port" ] && [ -n "$internal_ip" ] && [ -n "$internal_port" ]; then
        desc="dnat ${iface} ${proto} ${ext_port}->${internal_ip}:${internal_port}"
        rules="rdr on ${iface} proto ${proto} from any to (${iface}) port ${ext_port} -> ${internal_ip} port ${internal_port}\npass in quick on ${iface} proto ${proto} from any to ${internal_ip} port ${internal_port} keep state"
        add_rule_group "$desc" "$rules"
    else
        log_event error "invalid port forward entry skipped: $entry"
    fi
done

if [ -n "$forward_current" ]; then
    # Build pairwise forward rules
    set -- $forward_current
    while [ "$#" -gt 0 ]; do
        iface_a=$1
        shift
        if [ "$#" -gt 0 ]; then
            for iface_b in "$@"; do
                desc="forward ${iface_a}<->${iface_b}"
                rules="pass quick on ${iface_a} from (${iface_a}:network) to (${iface_b}:network) keep state\npass quick on ${iface_b} from (${iface_b}:network) to (${iface_a}:network) keep state"
                add_rule_group "$desc" "$rules"
            done
        fi
    done

    set -- $forward_current
    iface_set="{"
    while [ "$#" -gt 0 ]; do
        iface_set="$iface_set $1"
        shift
        [ "$#" -gt 0 ] && iface_set="$iface_set,"
    done
    iface_set="$iface_set }"
    case "$(echo "$FIREWALL_DEFAULT_FORWARD" | tr 'A-Z' 'a-z')" in
        allow)
            add_rule_group "forward-default-allow" "pass quick on ${iface_set} all keep state"
            ;;
        *)
            add_rule_group "forward-default-deny" "block quick on ${iface_set} all"
            ;;
    esac
fi

VALID_RULES=""

for file in $RULE_FILES; do
    desc_file="${file%.rules}.desc"
    desc=$(cat "$desc_file" 2>/dev/null)
    candidate=$(cat "$file")
    test_file="$workdir/candidate.conf"
    if [ -n "$VALID_RULES" ]; then
        printf '%s\n\n%s\n\n%s\n' "$BASE_RULES" "$VALID_RULES" "$candidate" >"$test_file"
    else
        printf '%s\n\n%s\n' "$BASE_RULES" "$candidate" >"$test_file"
    fi
    if pfctl -n -a "$ANCHOR_NAME" -f "$test_file" 2>"$workdir/pf.err"; then
        if [ -n "$VALID_RULES" ]; then
            VALID_RULES="$VALID_RULES\n$candidate"
        else
            VALID_RULES="$candidate"
        fi
        log_event update "rule accepted: $desc"
    else
        err_text=$(cat "$workdir/pf.err")
        log_event error "rule skipped ($desc): $err_text"
    fi
    rm -f "$test_file" "$workdir/pf.err"
    rm -f "$file" "$desc_file"
    RULE_FILES=$(printf '%s' "$RULE_FILES" | sed "s# $file##")
    if [ -z "$VALID_RULES" ]; then
        continue
    fi
done

FINAL_FILE="$workdir/final.conf"
if [ -n "$VALID_RULES" ]; then
    printf '%s\n\n%s\n' "$BASE_RULES" "$VALID_RULES" >"$FINAL_FILE"
else
    printf '%s\n' "$BASE_RULES" >"$FINAL_FILE"
fi

if ! pfctl -n -a "$ANCHOR_NAME" -f "$FINAL_FILE" 2>"$workdir/pf-final.err"; then
    err_text=$(cat "$workdir/pf-final.err")
    log_event error "pfctl validation failed: $err_text"
    exit 1
fi

if pfctl -a "$ANCHOR_NAME" -f "$FINAL_FILE" 2>"$workdir/pf-apply.err"; then
    log_event apply "pf rules updated successfully"
else
    err_text=$(cat "$workdir/pf-apply.err")
    log_event error "failed to apply pf rules: $err_text"
    exit 1
fi

cat >"$STATE_FILE" <<STATE
PREV_FIREWALL_NAT_OUT_IF="${FIREWALL_NAT_OUT_IF}"
PREV_FIREWALL_NAT_NETS="${FIREWALL_NAT_NETS}"
PREV_FIREWALL_NAT_HOSTS="${FIREWALL_NAT_HOSTS}"
PREV_FIREWALL_NAT_ALLOW_NETS="${FIREWALL_NAT_ALLOW_NETS}"
PREV_FIREWALL_BLOCK_NETS="${FIREWALL_BLOCK_NETS}"
PREV_FIREWALL_PORT_FORWARD_LIST="${FIREWALL_PORT_FORWARD_LIST}"
PREV_FIREWALL_FORWARD_ALLOW="${FIREWALL_FORWARD_ALLOW}"
PREV_FIREWALL_DEFAULT_FORWARD="${FIREWALL_DEFAULT_FORWARD}"
PREV_CONTEXT_SOURCE="${CONTEXT_SOURCE}"
STATE

cleanup
trap - EXIT INT TERM

log_event update "state updated in $STATE_FILE"
exit 0
