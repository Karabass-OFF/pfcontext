# Модуль межсетевого экрана ContextFW

**ContextFW** расширяет workflow pfSense ContextOnly и автоматически
конфигурирует NAT, проброс портов и межсетевой фильтр на основе переменных,
передаваемых в ISO `context.sh` из OpenNebula. Модуль располагается в
`/etc/context.d/firewall` и вызывается из скрипта ContextOnly сразу после того,
как настроены сетевые интерфейсы и создана временная копия `backup_xml_file`.

## Состав директории

```
/etc/context.d/firewall/
├── firewall.sh      # точка входа, оркестровка модуля
├── functions.sh     # логирование, блокировки, управление состоянием
├── vars.sh          # загрузка переменных из context.sh
├── mod_nat.sh       # исходящий NAT и управление алиасами
├── mod_dnat.sh      # правила DNAT (port forwarding)
├── mod_forward.sh   # политика межсетевого обмена между LAN
└── README.md        # описание логики
```

Каждый скрипт написан на POSIX `sh`, ведёт журнал в
`/var/log/context-firewall.log` (если `FIREWALL_LOG` не отключён) и создаёт
объекты только с префиксом `ContextFW:` в поле `descr`, чтобы не затрагивать
правила, добавленные через веб-интерфейс.

## Общий алгоритм

1. `firewall.sh` берёт блокировку `/var/run/context-firewall.lock`, загружает
   переменные через `vars.sh` и включает отладку при `FIREWALL_DEBUG=on`.
2. Все изменения выполняются над рабочей копией конфигурации, которую ContextOnly
   предварительно сохраняет в переменной `backup_xml_file`.
3. Подмодули вносят правки в XML:
   - **mod_nat.sh** переводит outbound NAT в режим *manual/advanced*, синхронизирует
     алиасы для `FIREWALL_NAT_ALLOW_NETS` и `FIREWALL_BLOCK_NETS`, а также
     пересобирает правила исходящего NAT для сетей и хостов из
     `FIREWALL_NAT_NETS` / `FIREWALL_NAT_HOSTS` на интерфейсе
     `FIREWALL_NAT_OUT_IF`.
   - **mod_dnat.sh** разбирает `FIREWALL_PORT_FORWARD_LIST` (правила разделены
     точкой с запятой, внутри — пары `ключ=значение` через запятую) и добавляет
     соответствующие правила проброса портов, опционально создавая связанные
     фильтрующие правила в `<filter><rule>`.
   - **mod_forward.sh** реализует политику межсетевого обмена на основе
     `FIREWALL_DEFAULT_FORWARD`, `FIREWALL_FORWARD_ALLOW_IF` и
     `FIREWALL_FORWARD_ALLOW_IP`, а также учитывает алиас блокируемых сетей из
     `FIREWALL_BLOCK_NETS`. Дополнительно выполняется fail-safe проверка на
     наличие неуправляемых правил, разрешающих LAN↔LAN трафик.
4. После модификации конфигурации запускается `php /etc/rc.filter_configure_sync`
   для генерации `/tmp/rules.debug`, затем выполняется проверка
   `pfctl -nf /tmp/rules.debug`. При успехе делается резервная копия
   `/cf/conf/config.xml`, новая версия атомарно перемещается на место, и
   выполняется `/usr/local/sbin/pfSsh.php playback reloadfilter` (если
   `FIREWALL_RELOAD=auto`). В ручном режиме (`manual`) изменения сохраняются, но
   применение откладывается и в журнал добавляется запись `[pending]`.
5. Файл состояния `/var/run/context-firewall.state` фиксирует контрольные суммы
   обработанных переменных и флаг отложенной перезагрузки. Пока флаг не снят
   вручную командой `pfSsh.php playback reloadfilter`, модуль повторно изменения
   не применяет.

При ошибках проверки (`pfctl -nf`) или загрузки правил выполняется откат к
последнему бэкапу из `/cf/conf/backup`, что обеспечивает безопасное завершение.

## Переменные context.sh

| Переменная | Назначение |
| --- | --- |
| `FIREWALL_ENABLE` | `on`/`off` — глобальное включение модуля. |
| `FIREWALL_DEBUG` | `on` — расширенное логирование и `set -x`. |
| `FIREWALL_LOG` | `off` — отключить запись в журнал. |
| `FIREWALL_PFCTL` | `off` — пропустить выполнение. |
| `FIREWALL_RELOAD` | `auto` — применить сразу; `manual` — только сохранить конфиг. |
| `FIREWALL_NAT_OUT_IF` | Интерфейс исходящего NAT. |
| `FIREWALL_NAT_NETS` / `FIREWALL_NAT_HOSTS` | Сети/хосты, которым нужен исходящий NAT. |
| `FIREWALL_PORT_FORWARD_LIST` | Список DNAT в формате `ключ=значение`, разделённый `;`. |
| `FIREWALL_FORWARD_ALLOW_IF` | Разрешённые пары интерфейсов (через запятую или пробел). |
| `FIREWALL_FORWARD_ALLOW_IP` | Разрешённые IP-адреса для межсетевого обмена. |
| `FIREWALL_DEFAULT_FORWARD` | Базовая политика `allow`/`deny` для LAN. |
| `FIREWALL_NAT_ALLOW_NETS` | Сети для алиаса `ContextFW_NAT_ALLOW`. |
| `FIREWALL_BLOCK_NETS` | Сети для алиаса `ContextFW_BLOCK_NETS`. |

## Тестирование и запуск

1. Смонтируйте ISO context и убедитесь, что `context.sh` экспортирует требуемые
   переменные. ContextOnly создаёт копию `/cf/conf/config.xml`, сохраняет путь в
   `backup_xml_file`, после чего вызывает `/etc/context.d/firewall/firewall.sh`.
2. Просмотрите `/var/log/context-firewall.log`, чтобы увидеть записи вида
   `[INFO] ContextFW module start`, действия `apply/update/remove` и строки о
   перезагрузке правил или уведомление `[pending] Reload skipped (manual mode)`.
3. Для лабораторной проверки можно запустить модуль вручную с тестовым набором
   переменных:

   ```sh
   # экспортируйте нужные FIREWALL_* переменные
   backup_xml_file=/tmp/config.xml.test
   cp /cf/conf/config.xml "$backup_xml_file"
   /etc/context.d/firewall/firewall.sh
   ```

   После выполнения проверьте конфигурацию командой `pfctl -nf /tmp/rules.debug`
   или изучите временные файлы, созданные модулем.

## Логирование

Журнал `/var/log/context-firewall.log` содержит записи с префиксами `[INFO]`,
`[WARN]`, `[ERROR]` и `[DEBUG]` (при активном `FIREWALL_DEBUG`). В ручном режиме
перезагрузки фиксируется запись `[pending]`, а состояние откладывается до ручного
вызова `/usr/local/sbin/pfSsh.php playback reloadfilter`.
