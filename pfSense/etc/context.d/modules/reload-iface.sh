# shellcheck disable=SC1091,SC2148,SC2154
# Reload pfSense services (if specified in the context)
if [ "${RC_RELOAD_ALL}" = "YES" ]; then
    # Перезагружаем службы pfSense
   {    /etc/rc.reload_all start
        echo "$(date) [context:reload-iface.sh] pfSense services reloaded"
        pfSsh.php playback restartallwan
        echo "$(date) [context:reload-iface.sh] pfSense services restarted"
    } >>"$LOG" 2>&1
fi
echo "$(date) [context:reload-iface.sh] RC_RELOAD_IFACE=${RC_RELOAD_IFACE}" >> "$LOG"

# Reload pfSense interfaces (if specified in the context)
if [ "${RC_RELOAD_IFACE}" = "YES" ]; then
    echo "$(date) [context:reload-iface.sh]  ${RC_RELOAD_IFACE} or PID file detected $PID" 
    ChatGPT сказал:

# Reload pfSense interfaces
    {   pfSsh.php playback restartallwan
        echo "$(date) [context:reload-iface.sh] pfSense services restarted"
    } >>"$LOG" 2>&1
fi

# disable/enable the pfSense firewall (pfctl)
echo "$(date) [context:reload-iface.sh] pfSense firewall switch = ${PFCTL}" >> "$LOG"
if [ -n "${PFCTL:-}" ]; then 
# Convert the value to lowercase for easier comparison  
    _lc_pfctl=$(echo "${PFCTL}" | tr '[:upper:]' '[:lower:]')
    case "$_lc_pfctl" in
        no|0)
            {
                if pfctl -s info 2>/dev/null | grep -qi 'Status: Enabled'; then
                    pfctl -d
                    echo "$(date) [context:reload-iface.sh] pfSense firewall disabled"
                else
                    echo "$(date) [context:reload-iface.sh] pfSense firewall already disabled (pf not enabled)"
                fi
                echo "$$" > /var/run/pfctlcontext.pid
                echo "$(date) [context:reload-iface.sh] Created pid file: /var/run/pfctlcontext.pid"
            } >> "$LOG" 2>&1
            ;;
        yes|1)
            if pfctl -s info | grep -qi 'Status: Disabled'; then
                {
                    echo "$(date) [context:reload-iface.sh] pfSense firewall was disabled, enabling now '${PFCTL}'"
                    rm -rf /var/run/pfctlcontext.pid
                    echo "$(date) [context:reload-iface.sh] Removed pid file: /var/run/pfctlcontext.pid"
                    pfctl -e
                    echo "$(date) [context:reload-iface.sh] pfSense firewall enabled"
                } >> "$LOG" 2>&1
            fi
            ;;
        *)
            echo "$(date) [context:reload-iface.sh] pfSense firewall state unchanged (PFCTL=$_lc_pfctl)" >> "$LOG"
            ;;
    esac
fi
