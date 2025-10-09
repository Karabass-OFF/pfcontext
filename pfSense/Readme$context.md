# ContextOnly

## Назначение
Основной модуль контекста pfSense. Считывает переменные OpenNebula из `context.sh`, сопоставляет их с системными интерфейсами по MAC-адресу и вносит изменения в `config.xml`. Дополнительно настраивает DNS, имя хоста, пароль администратора, состояние pf и запускает дочерние сценарии (`bgp`).

## Схема запуска
1. Служба `context` стартует из `<earlyshellcmd>` или вручную (`/etc/rc.d/context onestart`).
2. Скрипт монтирует ISO с контекстом (`/dev/cd0` → `/mnt/context`) и выполняет `context.sh`.
3. Создаётся резервная копия `config.xml` в `/cf/conf/backup/config.xml.<timestamp>`.
4. На основе переменных `ETHx_*`/`ETHERNETx_*` вычисляется сопоставление интерфейсов, IP-адресов и ролей (LAN/WAN/OPTn).
5. При необходимости интерфейсы пересоздаются, DHCP-блоки актуализируются, обновляются DNS, пароль, hostname, статус pf.
6. Если обнаружены изменения — файл конфигурации перезаписывается и выполняется `rc.reload_all` + `restartallwan`.
7. Скрипт отмонтирует ISO, вызывает `/etc/context.d/bgp` (если доступен) и удаляет `net.pid`.

## Переменные контекста

### Обязательные для интерфейсов
| Переменная | Описание |
|------------|----------|
| `ETHx_MAC` / `ETHERNETx_MAC` | MAC-адрес, по которому интерфейс сопоставляется с системным `ifconfig`. |
| `ETHx_IP` / `ETHERNETx_IP` | IPv4-адрес интерфейса. |
| `ETHx_MASK` / `ETHERNETx_MASK` | Маска сети в десятичном виде (например `255.255.255.0`). |

### Дополнительные параметры интерфейсов
| Переменная | Описание |
|------------|----------|
| `ETHx_GATEWAY` | Шлюз по умолчанию. Применяется для `wan` и прописывается в `system/gateway`. |
| `ETHx_TYPE` / `ETHERNETx_TYPE` | Роль интерфейса: `lan`, `wan` или `optN`. Дубликаты ролей автоматически переводятся в `OPT`. |
| `ETHx_DNS` | Пробельный список DNS-серверов. Первые два значения попадают в `/etc/resolv.conf` и `system/dnsserver`. |
| `ETHx_DHCP_START` / `ETHx_DHCP_END` | Если оба заданы — создаётся блок DHCP на интерфейсе; иначе существующий блок удаляется. |

### Глобальные параметры
| Переменная | Описание |
|------------|----------|
| `SSH_PUBLIC_KEY` | Добавляется в `/root/.ssh/authorized_keys` (повторно проверяется после выполнения). |
| `SET_HOSTNAME` | Устанавливает `hostname` и записывает значение в `system/hostname`. |
| `PFCTL` | Управление фаерволом: `off/false/0` — выключить pf; `on/true/1` — включить, если был выключен. |
| `PASSWORD` | Новый пароль пользователя `admin`. Проверяется через `password_verify`; изменяется через `pfSsh.php playback ChangePassTool`. |

## Примеры логов
```
Wed Oct  8 19:09:34 +05 2025 [context] Found /mnt/context/context.sh — sourcing
Wed Oct  8 19:09:34 +05 2025 [context] Added vtnet0 → LAN (172.20.14.43/29)
Wed Oct  8 19:09:34 +05 2025 [context] Gateway: 172.20.14.41
Wed Oct  8 19:09:34 +05 2025 [context] Set DNS: 8.8.8.8 8.8.8.8
Wed Oct  8 19:09:34 +05 2025 [context] pfSense firewall disabled
Wed Oct  8 19:09:34 +05 2025 [context] Running BGP module /etc/context.d/bgp
```
Результат — интерфейсы в `Interfaces > Assignments` обновляются согласно ролям, `config.xml` получает актуальные IP/descr, а `/tmp/context.log` фиксирует ход выполнения.

## Порядок установки и проверки
1. Скопируйте `ContextOnly` в `/etc/context.d/` и сделайте исполняемым: `chmod +x /etc/context.d/ContextOnly`.
2. Убедитесь, что `<earlyshellcmd>` или ручной запуск `service context onestart` задействует скрипт.
3. После загрузки проверьте `/tmp/context.log` на наличие строк `Total interfaces configured` и `FINISH`.
4. При проблемах с привязкой ролей проверьте `TYPE mismatch` и `Duplicate ... request` в логе.
5. Для повторного применения удалите `/etc/context.d/net.pid` и запустите `service context restart`.
