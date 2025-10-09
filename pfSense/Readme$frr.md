# frr rc-скрипт

## Назначение
`/etc/context.d/frr` — адаптированный rc-скрипт для управления демонами FRR в pfSense. Предоставляет единый интерфейс `service frr start|stop|restart`, запускает `watchfrr`, `mgmtd`, `zebra` и другие выбранные сервисы, а также подгружает стартовую конфигурацию через `vtysh -b`.

## Схема запуска
1. При включении `frr_enable="YES"` (в `/etc/rc.conf.local`) команда `service frr start` вызывает скрипт.
2. Определяется список демонов (`frr_daemons`) и дополнительные флаги (`*_flags`).
3. При активном `watchfrr_enable=YES` старт выполняется через `watchfrr`, который затем рестартует все демоны и вызывает `vtysh -b`.
4. Функция `start_postcmd` может ожидать появления маршрута (`frr_wait_for`).
5. Команда `vtysh -b` подгружает конфигурацию из `/var/etc/frr/vtysh.conf` (генерируется модулем `bgp`).

## Переменные
Скрипт не использует переменные контекста. Управление происходит через параметры rc-системы:
| Параметр | Назначение |
|----------|-----------|
| `frr_enable` | Включает/выключает сервис. |
| `frr_daemons` | Перечень демонов (`mgmtd zebra bgpd ...`). |
| `watchfrr_enable` | Управление процессом `watchfrr`. |
| `frr_vtysh_boot` | Разрешает загрузку интегрированной конфигурации `vtysh -b`. |
| `frr_wait_for`, `frr_wait_seconds` | Ожидание появления маршрута. |
| `<daemon>_flags` | Дополнительные ключи конкретному демону (например, `bgpd_flags`). |

## Примеры вывода
```
# service frr start
Checking intergrated config...
Starting mgmtd.
Starting zebra.
Starting bgpd.
vtysh -b
```
Сообщения отображаются в консоли при запуске/остановке.

## Порядок установки и проверки
1. Скопируйте файл в `/etc/context.d/frr` или оставьте системную версию, если уже присутствует.
2. Пропишите нужные параметры в `/etc/rc.conf.local`, например:
   ```sh
   cat <<'CFG' >> /etc/rc.conf.local
   frr_enable="YES"
   frr_daemons="mgmtd zebra bgpd"
   watchfrr_enable="YES"
   CFG
   ```
3. Запустите `service frr start` и убедитесь, что процессы FRR активны (`ps aux | grep frr`).
4. Используйте `service frr status` для контроля.
