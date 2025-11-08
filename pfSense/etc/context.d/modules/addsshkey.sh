# shellcheck shell=sh disable=SC2034,SC2154
# SSH ключ (если указана переменная SSH_PUBLIC_KEY)
if [ -n "${SSH_PUBLIC_KEY:-}" ]; then
    mkdir -p /root/.ssh
    if [ ! -f /root/.ssh/authorized_keys ] || ! grep -Fxq "$SSH_PUBLIC_KEY" /root/.ssh/authorized_keys; then
        # кодируем ключ в base64 (без переносов строк)
        # pfSense stores SSH authorized keys in base64 format inside <authorizedkeys>
        # This ensures compatibility with pfSense GUI and PHP auth subsystem.
        ENC_KEY=$(printf '%s' "$SSH_PUBLIC_KEY" | base64 | tr -d '\n')
        if xml sel -t -v "//user[name='admin']/authorizedkeys" "$xml_file" >/dev/null 2>&1; then
            xml ed -L -u "//user[name='admin']/authorizedkeys" -v "$ENC_KEY" "$xml_file"
        else
            xml ed -L -s "//user[name='admin']" -t elem -n "authorizedkeys" -v "$ENC_KEY" "$xml_file"
        fi
        echo "$(date) [context] SSH public key updated in config.xml" >> "$LOG"
        echo "$SSH_PUBLIC_KEY" >> /root/.ssh/authorized_keys
        chmod 600 /root/.ssh/authorized_keys
        chmod 700 /root/.ssh
        echo "$(date) [context] SSH public key updated" >> "$LOG"
        #RC_RELOAD_ALL="on" && echo "$(date) [context] RC_RELOAD_ALL set to on due to SSH key change" >> "$LOG"
    fi
fi