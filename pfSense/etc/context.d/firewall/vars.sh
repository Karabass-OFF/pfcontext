#!/bin/sh
# Variable loader for context firewall module

PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin

load_context_vars() {
    CONTEXT_SOURCE=""
    if [ -n "${CONTEXT_FILE:-}" ]; then
        if [ -f "$CONTEXT_FILE" ]; then
            CONTEXT_SOURCE="$CONTEXT_FILE"
        fi
    fi

    if [ -z "$CONTEXT_SOURCE" ]; then
        for candidate in \
            /mnt/context/context.sh \
            /var/db/context/context.sh \
            /conf/context.sh \
            /tmp/context.sh \
            /etc/context.sh
        do
            if [ -f "$candidate" ]; then
                CONTEXT_SOURCE="$candidate"
                break
            fi
        done
    fi

    if [ -z "$CONTEXT_SOURCE" ]; then
        return 1
    fi

    # shellcheck source=/dev/null
    . "$CONTEXT_SOURCE"

    FIREWALL_ENABLE=${FIREWALL_ENABLE:-off}
    FIREWALL_PFCTL=${FIREWALL_PFCTL:-off}
    FIREWALL_NAT_OUT_IF=$(normalize_spaces "${FIREWALL_NAT_OUT_IF:-}")
    FIREWALL_FORWARD_ALLOW=$(normalize_spaces "${FIREWALL_FORWARD_ALLOW:-}")
    FIREWALL_NAT_NETS=$(normalize_spaces "${FIREWALL_NAT_NETS:-}")
    FIREWALL_NAT_HOSTS=$(normalize_spaces "${FIREWALL_NAT_HOSTS:-}")
    FIREWALL_NAT_ALLOW_NETS=$(normalize_spaces "${FIREWALL_NAT_ALLOW_NETS:-}")
    FIREWALL_BLOCK_NETS=$(normalize_spaces "${FIREWALL_BLOCK_NETS:-}")
    FIREWALL_PORT_FORWARD_LIST=$(normalize_spaces "${FIREWALL_PORT_FORWARD_LIST:-}")
    FIREWALL_DEFAULT_FORWARD=${FIREWALL_DEFAULT_FORWARD:-deny}
    FIREWALL_LOG=${FIREWALL_LOG:-on}
    FIREWALL_RELOAD=${FIREWALL_RELOAD:-auto}

    export FIREWALL_ENABLE FIREWALL_PFCTL FIREWALL_NAT_OUT_IF \
        FIREWALL_FORWARD_ALLOW FIREWALL_NAT_NETS FIREWALL_NAT_HOSTS \
        FIREWALL_NAT_ALLOW_NETS FIREWALL_BLOCK_NETS FIREWALL_PORT_FORWARD_LIST \
        FIREWALL_DEFAULT_FORWARD FIREWALL_LOG FIREWALL_RELOAD CONTEXT_SOURCE

    return 0
}
