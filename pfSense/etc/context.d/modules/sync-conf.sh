# shellcheck disable=SC1091,SC2148,SC2154
# Синхронизация config.xml (если есть изменения)
if diff -I '<bcrypt-hash>.*</bcrypt-hash>'  -I '<authorizedkeys>.*</authorizedkeys>' -q "$xml_file" "$backup_xml_file" >/dev/null; then
    rm -f "$backup_xml_file"
    echo "$(date) [context] No changes in config.xml, backup_xml_file removed" >> "$LOG"
elif [ -s "$backup_xml_file" ]; then # Если файл не пустой, копируем его в config.xml
    cp "$backup_xml_file" "$xml_file"
    echo "$(date) [context] config.xml updated, backup_xml_file saved to $backup_xml_file" >> "$LOG"
fi
