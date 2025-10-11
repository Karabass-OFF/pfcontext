# pfcontext

## Назначение проекта
pfcontext автоматизирует первичную настройку виртуальной машины pfSense, развёрнутой в OpenNebula. Скрипты читают файл `context.sh`, смонтированный из виртуального CD-ROM, и на основании переданных переменных обновляют `config.xml`, настраивают сетевые интерфейсы, службы pfSense и компоненты FRR/BGP. Это позволяет получить готовый к работе маршрутизатор сразу после первого запуска ВМ без ручного вмешательства.

## Структура репозитория
| Путь | Назначение |
| --- | --- |
| `pfSense/INSTALL` | Пошаговая инструкция по развёртыванию набора скриптов на узле pfSense: копирование файлов, установка зависимостей, применение патча к `/etc/rc.initial`, установка FRR и перезагрузка узла.【F:pfSense/INSTALL†L1-L29】 |
| `pfSense/tmp/rc.initial.patch` | Патч, который добавляет в ранний этап загрузки вызов `ResizeZfs` и `ContextOnly`, а также файл состояния, чтобы избежать повторного запуска в пределах первых трёх минут работы системы.【F:pfSense/tmp/rc.initial.patch†L1-L19】 |
| `pfSense/etc/context.d/ContextOnly` | Основной модуль контекста. Монтирует CD-ROM, читает `context.sh`, применяет сетевые настройки, обновляет DNS, имя хоста, управляет перезагрузкой служб, паролем `admin`, вызывается модуль BGP и добавляет SSH-ключ.【F:pfSense/etc/context.d/ContextOnly†L1-L405】 |
| `pfSense/etc/context.d/bgp` | Дополнительный модуль, который настраивает FRR/BGP на основе переменных контекста: собирает конфигурацию для `config.xml`, применяет её через PHP и `vtysh`, ведёт журнал и отслеживает изменения для инкрементального обновления.【F:pfSense/etc/context.d/bgp†L1-L527】 |
| `pfSense/etc/context.d/ResizeZfs` | Скрипт rc.d, который увеличивает ZFS-раздел/пул `pfSense`, если виртуальный диск был расширен, и записывает ход операций в журнал.【F:pfSense/etc/context.d/ResizeZfs†L1-L61】 |
| `pfSense/etc/context.d/pfctl_off` | Небольшой скрипт, который по PID-файлу решает, нужно ли периодически отключать pfctl (firewall) — вызывается из cron каждую минуту.【F:pfSense/etc/context.d/pfctl_off†L1-L21】 |
| `pfSense/etc/devd/context.conf` | Правила `devd`, которые запускают `ContextOnly` при появлении CD-ROM с контекстом, `ResizeZfs` при изменении размера виртуального диска и помечают необходимость перепривязки сетей при добавлении/удалении интерфейсов.【F:pfSense/etc/devd/context.conf†L1-L30】 |
| `pfSense/etc/cron.d/context` | Планировщик, ежеминутно вызывающий `pfctl_off`, чтобы гарантировать выключение firewall при необходимости.【F:pfSense/etc/cron.d/context†L1-L6】 |
| `pfSense/etc/phpshellsessions/ChangePassTool` | PHP-скрипт из pfSense для смены пароля пользователя `admin`, который используется модулем контекста при изменении переменной `PASSWORD`.【F:pfSense/etc/phpshellsessions/ChangePassTool†L1-L76】 |

## Последовательность выполнения и взаимосвязь модулей
1. **Загрузка pfSense и запуск ранних команд.** Патч `rc.initial` запускает `ResizeZfs onestart` и `ContextOnly onestart` один раз в первые 180 секунд аптайма, избегая повторов с помощью файла `/var/run/contextallrun_started`.【F:pfSense/tmp/rc.initial.patch†L5-L19】
2. **Обработка аппаратных событий.** `devd` дополнительно вызывает `ContextOnly`, когда в систему вставляется ISO `CONTEXT`, и `ResizeZfs` при изменении размера диска, а также отмечает изменения сетевых интерфейсов в `/etc/context.d/net.pid`.【F:pfSense/etc/devd/context.conf†L1-L29】
3. **Основной модуль ContextOnly.**
   - Монтирует CD-ROM `/dev/cd0` в `/mnt/context`, читает `context.sh`, делает резервную копию `config.xml` и подготавливает вспомогательную функцию `get_ctx_var` для чтения `ETHx_*` переменных.【F:pfSense/etc/context.d/ContextOnly†L7-L37】
   - Анализирует требуемые интерфейсы (MAC, типы), при необходимости очищает секцию `<interfaces>` в `config.xml`, сопоставляет MAC-адреса, назначает роли LAN/WAN/OPT, прописывает IP/маску/шлюз, отключает `blockpriv/bogons` на WAN и обновляет `config.xml`.【F:pfSense/etc/context.d/ContextOnly†L42-L295】
   - Собирает DNS-адреса, задаёт hostname, по опциям `RC_RELOAD_ALL`/`RC_RELOAD_IFACE` перезапускает службы/интерфейсы, управляет состоянием pfctl через `PFCTL`, обновляет пароль `admin`, размонтирует CD-ROM и запускает модуль BGP, если он доступен.【F:pfSense/etc/context.d/ContextOnly†L299-L389】
   - При наличии `SSH_PUBLIC_KEY` добавляет ключ в `/root/.ssh/authorized_keys`.【F:pfSense/etc/context.d/ContextOnly†L390-L399】
4. **Модуль BGP.** Запускается из `ContextOnly` и выполняет полную цепочку проверки зависимостей FRR, подгрузки `context.sh` при необходимости, генерации `config.xml` через PHP и применения настроек в рантайме через `vtysh`. Для предотвращения избыточных изменений хранит контрольные суммы и состояния сетей/соседей в `/var/run/context-bgp.*`.【F:pfSense/etc/context.d/bgp†L13-L526】
5. **ResizeZfs.** Может запускаться как на старте, так и при событиях `devd`; расширяет ZFS-раздел и пул `pfSense`, если обнаружено свободное место и нет повреждений GPT.【F:pfSense/etc/context.d/ResizeZfs†L29-L57】
6. **Периодический контроль firewall.** `cron` каждую минуту запускает `pfctl_off`, который отключает pfctl, если существует PID-файл `/var/run/pfctlcontext.pid`. Это позволяет оставлять firewall выключенным до завершения контекстной инициализации.【F:pfSense/etc/context.d/pfctl_off†L3-L18】【F:pfSense/etc/cron.d/context†L1-L6】

Рекомендуемый альтернативный запуск без патча — прописать `<earlyshellcmd>/etc/context.d/ContextOnly onestart</earlyshellcmd>` в `config.xml`, о чём напоминает заголовок `ResizeZfs`, однако текущая поставка использует именно патч `rc.initial`.【F:pfSense/etc/context.d/ResizeZfs†L3-L7】

## Процесс установки
1. Скопируйте содержимое каталога `pfSense` на целевую систему (например, через `scp -r ./ root@pfSense:/`).【F:pfSense/INSTALL†L3-L6】
2. Установите зависимости:
   - `xmlstarlet` (команда `pkg install -y xmlstarlet`) — предоставляет утилиту `xml`, которой оперирует `ContextOnly` для редактирования `config.xml` и чтения текущих значений.【F:pfSense/etc/context.d/ContextOnly†L47-L288】【F:pfSense/INSTALL†L7-L10】
   - `php` CLI — уже входит в pfSense, но модуль BGP проверяет наличие `/usr/local/bin/php`; убедитесь, что пакет установлен.【F:pfSense/etc/context.d/bgp†L20-L34】
   - `pfSense-pkg-frr` или `frr9` — обязательны для работы BGP-модуля; устанавливаются через `pkg install` (скрипт предлагает найти актуальный пакет командой `pkg search -x frr`).【F:pfSense/etc/context.d/bgp†L13-L17】【F:pfSense/INSTALL†L20-L25】
3. Примените патч `/tmp/rc.initial.patch`, чтобы добавить автозапуск контекста на ранней стадии загрузки (рекомендуется сначала выполнить `--dry-run`).【F:pfSense/INSTALL†L11-L14】【F:pfSense/tmp/rc.initial.patch†L5-L19】
4. При необходимости очистите логи/бэкапы (опциональный шаг из исходной инструкции).【F:pfSense/INSTALL†L15-L19】
5. Перезагрузите устройство pfSense, чтобы запустился новый поток инициализации.【F:pfSense/INSTALL†L26-L29】

### Активация автозапуска
После копирования файлов и применения патча достаточно перезагрузки. Если патч не используется, можно вручную выполнить:
```sh
xmlstarlet ed -L -s '/pfsense/system' -t elem -n earlyshellcmd -v '/etc/context.d/ContextOnly onestart' /cf/conf/config.xml
```
и затем перезапустить pfSense — запись `earlyshellcmd` активирует запуск скрипта на этапе загрузки (аналогично указанию в комментарии `ResizeZfs`).【F:pfSense/etc/context.d/ResizeZfs†L3-L7】

### Возможные улучшения процесса установки
- Объединить шаги установки зависимостей в один скрипт, например `install.sh`, который автоматически вызывает `pkg install -y xmlstarlet pfSense-pkg-frr` и копирует файлы.
- Вместо ручного патча `rc.initial` рассмотреть использование стандартной механики `earlyshellcmd` и `devd`, чтобы избежать конфликтов при обновлениях pfSense.
- Добавить проверку целостности и резервное копирование исходного `rc.initial` перед применением патча.

## Переменные контекста
Все переменные передаются через `context.sh`, который предоставляет OpenNebula. Скрипт поддерживает два семейства префиксов (`ETHx_*` и `ETHERNETx_*`) — они взаимозаменяемы. Ниже приведены основные группы.

### Сетевые параметры
| Переменная | Назначение |
| --- | --- |
| `ETHx_MAC` / `ETHERNETx_MAC` | MAC-адрес сетевого интерфейса, по которому скрипт сопоставляет физический порт с параметрами контекста.【F:pfSense/etc/context.d/ContextOnly†L105-L116】 |
| `ETHx_TYPE` / `ETHERNETx_TYPE` | Требуемая роль интерфейса: `lan`, `wan` или `optN`. Влияет на то, какой раздел `<interfaces>` будет создан и какие резервные имена будут заняты заранее (учитываются явные запросы LAN/WAN).【F:pfSense/etc/context.d/ContextOnly†L76-L210】 |
| `ETHx_IP` | IPv4-адрес интерфейса. Используется совместно с `MASK` для настройки стека и записи в `config.xml`.【F:pfSense/etc/context.d/ContextOnly†L110-L269】 |
| `ETHx_MASK` | Маска сети. Скрипт пересчитывает её в префикс (/CIDR) и сохраняет в `config.xml` и интерфейсной конфигурации.【F:pfSense/etc/context.d/ContextOnly†L254-L269】 |
| `ETHx_GATEWAY` | Шлюз по умолчанию для данного интерфейса. Применяется только к WAN: создаёт маршрут по умолчанию, отключает `blockpriv`/`blockbogons` и прописывает `WANGW` в `config.xml`.【F:pfSense/etc/context.d/ContextOnly†L275-L290】 |
| `ETHx_DNS` | Список DNS-адресов (принимает пробелы или несколько значений). Первый и последний элемент попадают в `/etc/resolv.conf` и `config.xml`, а также отключается `dnsallowoverride`.【F:pfSense/etc/context.d/ContextOnly†L299-L317】 |

Дополнительно, если тип не указан, скрипт автоматически назначает `lan` для приватных сетей и `wan` для публичных, заполняя остальные интерфейсы последовательными `optN`.【F:pfSense/etc/context.d/ContextOnly†L211-L250】

### Сервисные параметры
| Переменная | Назначение |
| --- | --- |
| `PFCTL` | Управление состоянием firewall: значения `off`, `0`, `false`, `disabled` выключают pfctl; `on`, `1`, `true`, `enabled` включают (если был выключен).【F:pfSense/etc/context.d/ContextOnly†L348-L368】 |
| `RC_RELOAD_ALL` | Если установлено в `on`, после сохранения `config.xml` запускается `/etc/rc.reload_all` и `pfSsh.php playback restartallwan` для полной перезагрузки сервисов.【F:pfSense/etc/context.d/ContextOnly†L332-L340】 |
| `RC_RELOAD_IFACE` | При значении `on` инициирует перезапуск WAN-интерфейсов через `pfSsh.php playback restartallwan`. Полезно при обновлении адреса без полной перезагрузки сервисов.【F:pfSense/etc/context.d/ContextOnly†L341-L345】 |
| `PASSWORD` | Новый пароль пользователя `admin`. Скрипт сравнивает его с текущим хэшем в `config.xml` и при отличии запускает `ChangePassTool`.【F:pfSense/etc/context.d/ContextOnly†L369-L376】【F:pfSense/etc/phpshellsessions/ChangePassTool†L21-L76】 |
| `SSH_PUBLIC_KEY` | Публичный ключ, добавляемый в `/root/.ssh/authorized_keys` (если такого ключа ещё нет). Позволяет включить беспарольный доступ по SSH.【F:pfSense/etc/context.d/ContextOnly†L390-L399】 |
| `BGP_ENABLE` | Включение модуля BGP (значение `on`). Если параметр выключен или отсутствует, модуль завершается без изменений.【F:pfSense/etc/context.d/bgp†L138-L142】 |
| `BGP_AS`, `BGP_ROUTER_ID` | Номер автономной системы и router-id для BGP; обязательны при `BGP_ENABLE=on`.【F:pfSense/etc/context.d/bgp†L138-L142】 |
| `BGP_NEIGHBORS` | Список соседей через пробел/точку с запятой в формате `IP,ASN,password`. Используется для генерации записей `frrbgpneighbors` и конфигурации `vtysh`. Пароль может быть опущен.【F:pfSense/etc/context.d/bgp†L184-L205】【F:pfSense/etc/context.d/bgp†L337-L352】【F:pfSense/etc/context.d/bgp†L497-L524】 |
| `BGP_NETWORKS_TO_DISTRIBUTE` | Список сетей для анонса, формат `CIDR,RouteMap`. Если route-map не указан, берётся значение `BGP_RMAP_DEFAULT`.【F:pfSense/etc/context.d/bgp†L206-L225】【F:pfSense/etc/context.d/bgp†L360-L425】 |
| `BGP_RMAP_DEFAULT` | Имя route-map по умолчанию. Создаётся секция `frrglobalroutemaps` и используется для соседей/сетей, если не задано иное.【F:pfSense/etc/context.d/bgp†L205-L266】 |
| `BGP_ADJACENCY_LOG`, `BGP_REDIST_CONNECTED`, `BGP_REDIST_STATIC`, `BGP_REDIST_KERNEL` | Управляют соответствующими флагами BGP (включение логирования сессий и перераспределение маршрутов).【F:pfSense/etc/context.d/bgp†L275-L282】 |
| `FRR_ENABLE`, `FRR_DEFAULT_ROUTER_ID`, `FRR_MASTER_PASSWORD`, `FRR_PASSWORD_ENCRYPT` | Глобальные настройки пакета FRR, отражаются в `installedpackages.frr`. Пароль может храниться в зашифрованном виде при `FRR_PASSWORD_ENCRYPT=on`.【F:pfSense/etc/context.d/bgp†L91-L137】【F:pfSense/etc/context.d/bgp†L247-L259】 |

### Системные/служебные параметры
| Переменная | Назначение |
| --- | --- |
| `SET_HOSTNAME` | Имя хоста, которое записывается в систему и `config.xml`.【F:pfSense/etc/context.d/ContextOnly†L319-L324】 |
| `RC_RELOAD_ALL` / `RC_RELOAD_IFACE` | Управление перезапуском служб/интерфейсов после изменения `config.xml`.【F:pfSense/etc/context.d/ContextOnly†L332-L345】 |
| `CONTEXT`-переменные среды | Внутренние переменные (`CONTEXT_MOUNT`, `CONTEXT_DEV`, `PID`) управляют процессом монтирования ISO и отслеживанием изменений интерфейсов. Пользователю их задавать не нужно, но важно знать о лог-файле `/var/log/context.log`.【F:pfSense/etc/context.d/ContextOnly†L7-L45】 |

## Пример файла `context.sh`
```sh
# Привязка интерфейсов по MAC-адресам
ETH0_MAC="00:50:56:aa:bb:01"
ETH0_TYPE="wan"
ETH0_IP="203.0.113.10"
ETH0_MASK="255.255.255.252"
ETH0_GATEWAY="203.0.113.9"
ETH0_DNS="8.8.8.8 1.1.1.1"

ETH1_MAC="00:50:56:aa:bb:02"
ETH1_TYPE="lan"
ETH1_IP="192.168.10.1"
ETH1_MASK="255.255.255.0"
ETH1_DNS="192.168.10.1"

SET_HOSTNAME="pfsense-demo"
PFCTL="off"
RC_RELOAD_ALL="on"
PASSWORD="SuperSecret123"
SSH_PUBLIC_KEY="ssh-ed25519 AAAAC3Nz... user@example"

# BGP и FRR
FRR_ENABLE="on"
FRR_DEFAULT_ROUTER_ID="192.0.2.1"
BGP_ENABLE="on"
BGP_AS="65001"
BGP_ROUTER_ID="192.0.2.1"
BGP_RMAP_DEFAULT="ALL"
BGP_NETWORKS_TO_DISTRIBUTE="192.168.10.0/24,ALL"
BGP_NEIGHBORS="198.51.100.2,65002,s3cr3t"
BGP_REDIST_CONNECTED="yes"
BGP_REDIST_STATIC="no"
```

## Отладка и эксплуатационные заметки
- Основной журнал инициализации: `/var/log/context.log`. Здесь фиксируется ход работы `ContextOnly`, включая монтирование ISO, настройку интерфейсов, DNS, изменение пароля, выполнение BGP-модуля и т.д.【F:pfSense/etc/context.d/ContextOnly†L7-L405】
- Журнал BGP: `/var/log/context-bgp.log`, создаётся модулем `bgp` и содержит подробности применения FRR-конфигурации.【F:pfSense/etc/context.d/bgp†L5-L527】
- Повторный запуск контекста вручную: `/etc/context.d/ContextOnly onestart` (аналогично можно перезапустить `ResizeZfs`). Полезно после ручного редактирования `context.sh` без перезагрузки.
- Проверка установки пакетов: `pkg info xmlstarlet`, `pkg info pfSense-pkg-frr` или `pkg info frr9` помогают убедиться, что зависимые утилиты доступны.【F:pfSense/etc/context.d/bgp†L13-L21】
- Если firewall отключён через `PFCTL=off`, убедитесь, что создан PID-файл `/var/run/pfctlcontext.pid` (его создание должно выполнять внешняя логика) — иначе cron-задача не будет вмешиваться.【F:pfSense/etc/context.d/pfctl_off†L4-L18】
- При расширении диска проверьте вывод `zpool list pfSense` и логи `ResizeZfs`, чтобы убедиться, что zpool увеличен.【F:pfSense/etc/context.d/ResizeZfs†L29-L53】

Соблюдение этих шагов обеспечивает корректное автоматическое конфигурирование pfSense в инфраструктуре OpenNebula, а README выступает в качестве справочника для администраторов.
