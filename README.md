# pfcontext

## Назначение проекта
Автоматизация первичной настройки виртуальной машины pfSense, развёрнутой в OpenNebula. Скрипты читают файл `context.sh` из виртуального CD-ROM, и на основании переданных переменных обновляют `config.xml`, настраивают сетевые интерфейсы, службы pfSense и компоненты FRR/BGP. Это позволяет получить готовый к работе маршрутизатор сразу после первого запуска ВМ без ручного вмешательства.

## Структура репозитория
| Путь | Назначение |
| --- | --- |
| `pfSense/INSTALL` | Краткий чек-лист развертывания пакета контекстных скриптов на pfSense. |
| `pfSense/etc/rc.initial` | Модифицированный `rc.initial`, который в первые ~120 секунд аптайма последовательно запускает `/etc/context.d/modules/ResizeZfs` и `ContextOnly`, отмечая успешный старт в `/var/run/contextallrun_started`. |
| `pfSense/etc/context.d/ContextOnly` | Основной модуль: читает `context.sh`, применяет сеть, системные параметры и вызывает дочерние модули. |
| `pfSense/etc/context.d/VERSION` | Текстовая версия пакета, отображаемая в логах. |
| `pfSense/etc/context.d/modules/ResizeZfs` | Расширение ZFS-раздела и пула при увеличении виртуального диска. |
| `pfSense/etc/context.d/modules/addsshkey.sh` | Добавляет публичный ключ `SSH_PUBLIC_KEY` в `/root/.ssh/authorized_keys` и `config.xml` (base64). |
| `pfSense/etc/context.d/modules/bgp` | Интеграция с FRR/BGP и инкрементальное обновление маршрутизации. |
| `pfSense/etc/context.d/modules/ipsec.sh` | Генерация и идемпотентное обновление IPsec-туннелей, управление strongSwan и вызов плагинов. |
| `pfSense/etc/context.d/modules/ipsec-plugins/firewall-rules.sh` | Создает/обновляет IKE/NAT-T/ESP правила на интерфейсах Phase1 и универсальные allow-all правила на IPsec/enc0. |
| `pfSense/etc/context.d/modules/ipsec-plugins/strat-nonblok.sh` | Немедленно инициирует все IPsec-соединения через `swanctl`, не блокируя основной поток. |
| `pfSense/etc/context.d/modules/mgmt.sh` | Управление выделенным MGMT-интерфейсом: алиасы, правила firewall и anti-lockout. |
| `pfSense/etc/context.d/modules/nat.sh` | Выставляет режим outbound NAT (automatic/hybrid/advanced/disabled) и при необходимости добавляет на выбранном интерфейсе правило allow-any с отрицанием IP самого интерфейса. |
| `pfSense/etc/context.d/modules/pfctl.sh` | Управляет WAN-настройками (gateway, blockpriv/bogons) и решает, нужно ли перезапускать интерфейсы. |
| `pfSense/etc/context.d/modules/reload-iface.sh` | Выполняет `rc.reload_all`, `restartallwan` и переключает `pfctl` в требуемое состояние. |
| `pfSense/etc/context.d/modules/pfctl_off` | Скрипт для cron: отключает pfctl по PID-файлу `/var/run/pfctlcontext.pid`. |
| `pfSense/etc/context.d/modules/sync-conf.sh` | Сравнивает `config.xml` и рабочую копию, сохраняет изменения при необходимости. |
| `pfSense/etc/devd/context.conf` | Триггеры `devd` для запуска контекста при событиях CD-ROM/диска/интерфейсов. |
| `pfSense/etc/cron.d/context` | Cron-задачи: каждую минуту вызывается `pfctl_off`, а при загрузке (`@reboot`) через 180 секунд гарантируется наличие файла `/etc/context.d/firstboot` (модули продолжают выполняться, пока переменная `FIRST_BOOT` не переключена в `NO`). |
| `pfSense/etc/phpshellsessions/ChangePassTool` | Скрипт pfSense для смены пароля `admin`, используемый контекстом. |

## Последовательность выполнения и взаимосвязь модулей
1. **Загрузка pfSense и запуск ранних команд.** Патч `rc.initial` добавляет последовательный вызов `/etc/context.d/modules/ResizeZfs` и `ContextOnly`, поэтому сценарии стартуют в штатной цепочке загрузки сразу после монтирования конфигурации.
2. **Обработка аппаратных событий.** `devd` дополнительно вызывает `ContextOnly`, когда в систему вставляется ISO `CONTEXT`, и `ResizeZfs` при изменении размера диска, а также отмечает изменения сетевых интерфейсов в `/etc/context.d/net.pid`.
3. **Основной модуль ContextOnly.**
     - Монтирует CD-ROM `/dev/cd0` в `/mnt/context`, читает `context.sh`, делает резервную копию `config.xml`, подготавливает вспомогательную функцию `get_ctx_var` и файл для работы `xmlstarlet`.
   - Анализирует требуемые интерфейсы (MAC, типы), при необходимости очищает секцию `<interfaces>` в `config.xml`, сопоставляет MAC-адреса, назначает роли LAN/WAN/OPT, прописывает IP/маску/шлюз и обновляет конфигурацию.
   - Собирает DNS-адреса, задаёт hostname, формирует флаги `RC_RELOAD_IFACE` и `PFCTL`, чтобы downstream-модули знали, что перезапускать; обновляет пароль `admin`, размонтирует CD-ROM и запускает модуль BGP, если он доступен.
   - При наличии `SSH_PUBLIC_KEY` кодирует ключ в Base64, записывает его в `config.xml` (секция пользователя `admin`) и добавляет в `/root/.ssh/authorized_keys`, чтобы ключ был доступен сразу после инициализации.
   - После применения правок вызывает `modules/sync-conf.sh`, который сравнивает рабочую копию `config.xml` с оригиналом и записывает изменения только при наличии дельты.
4. **Модуль BGP.** Запускается из `ContextOnly` и выполняет полную цепочку проверки зависимостей FRR, подгрузки `context.sh` при необходимости, генерации `config.xml` через PHP и применения настроек в рантайме через `vtysh`. Для предотвращения избыточных изменений хранит контрольные суммы и состояния сетей/соседей в `/var/run/context-bgp.*`.
5. **IPsec-модуль (`modules/ipsec.sh`).** При `CONTEXT_IPSEC_ENABLE=YES` читает параметры туннелей, задаёт дефолты Phase1/Phase2 для каждого индекса, идемпотентно создаёт или обновляет секции `phase1/phase2` в `config.xml`, вызывает `ipsec_configure()`, контролирует strongSwan и инициирует подключения через `swanctl`. Встроенные плагины `ipsec-plugins/firewall-rules.sh` и `ipsec-plugins/strat-nonblok.sh` автоматически создают IKE/NAT-T/ESP правила на нужных интерфейсах и немедленно запускают `swanctl --initiate` в неблокирующем режиме.
6. **Модуль NAT (`modules/nat.sh`).** При `NAT_ENABLE=YES` проверяет наличие интерфейса из `NAT_IF`, выставляет режим outbound NAT (automatic/hybrid/advanced/disabled), фиксирует результат в `config.xml`.
7. **Перезапуски служб и состояние pfctl (`modules/pfctl.sh`, `modules/reload-iface.sh`, `modules/pfctl_off`).** `pfctl.sh` управляет WAN-параметрами (удаляет дефолтный маршрут при включённом BGP, переключает `blockpriv/bogons`, считает хэш секции `<interfaces>`), а `reload-iface.sh` реагирует на флаги `RC_RELOAD_IFACE` и `PFCTL`: вызывает `rc.reload_all`/`restartallwan`, включает или отключает pfctl и при необходимости создаёт PID-файл `/var/run/pfctlcontext.pid`. Cron-задача `modules/pfctl_off` каждую минуту проверяет этот PID-файл и держит pfctl отключённым до завершения инициализации.
8. **Модуль управления management-интерфейсом (`modules/mgmt.sh`).** Активируется, когда в `context.sh` выставлено `MGMT_ENABLE=YES`: переводит выбранный логический интерфейс `MGMT_IF` в режим управляемого доступа, отключает anti-lockout веб-интерфейса, удаляет gateway, синхронизирует алиас `MGMT_PORTS`, строит ACL `[MGMT]` согласно источникам из `MGMT_SRC` и добавляет блокирующее правило `block any→mgmtIP` на задействованных интерфейсах. При `MGMT_ENABLE=NO` выполняет обратные операции и возвращает конфигурацию в исходное состояние.
9. **ResizeZfs.** Может запускаться как на старте, так и при событиях `devd`; расширяет ZFS-раздел и пул `pfSense`, если обнаружено свободное место и нет повреждений GPT.
Первичный запуск теперь осуществляется штатным механизмом pfSense. Контроль модулями `bgp`, `mgmt.sh`, `ipsec.sh` и `nat.sh` выполняется связкой флага `/etc/context.d/firstboot` и переменной `FIRST_BOOT`: при отсутствии флага блок выполняется принудительно, а при его наличии запуск пропускается только если в `context.sh` задано `FIRST_BOOT=NO` (значение `YES` инициирует повторный прогон).

## Процесс установки
1. Скопируйте содержимое каталога `pfSense` на целевую систему (например, через `scp -r ./ root@pfSense:/`).
2. Установите зависимости:
   - `xmlstarlet` (команда `pkg install -y xmlstarlet`) — предоставляет утилиту `xml`, которой оперирует `ContextOnly` для редактирования `config.xml` и чтения текущих значений.
   - `php` CLI — уже входит в pfSense, но модуль BGP проверяет наличие `/usr/local/bin/php`; убедитесь, что пакет установлен.
   - `pfSense-pkg-frr` или `frr9` — обязательны для работы BGP-модуля; устанавливаются через `pkg install` (скрипт предлагает найти актуальный пакет командой `pkg search -x frr`).
3. Добавьте ранний запуск контекста осушествляется через `/etc/rc.initial` следуйте подсказкам из `pfSense/INSTALL`.
4. При необходимости очистите логи/бэкапы (опциональный шаг из исходной инструкции).
5. Перезагрузите устройство pfSense, чтобы запустился новый поток инициализации.

## Переменные контекста
Все параметры задаются в `context.sh`, который подключается на раннем этапе загрузки. Ниже — пользовательские переменные, сгруппированные по функциям. 

### Системные/служебные 
| Переменная | Назначение |
| --- | --- |
| `SET_HOSTNAME` | Имя хоста, которое записывается в систему и `config.xml`. |
| `RC_RELOAD_IFACE` | Управление перезапуском служб/интерфейсов после изменения `config.xml`. |
| `FIRST_BOOT` | Контролирует запуск «первичных» модулей (`bgp`, `mgmt.sh`, `ipsec.sh`, `nat.sh`). Значение `NO` (установлено по умолчанию) заставляет модуль  каждом запуске чтобы пропустить повторный запуск после первичной инициализации; для ручного повторного старта временно верните `YES`. |

### Сеть
- `ETHERNETx_TYPE` — требуемая роль (`lan`, `wan`, `optN`), определяет раздел `<interfaces>`.

### Диск
- Дополнительных переменных не требуется — `ResizeZfs` расширяет пул автоматически при наличии свободного места.

### Фаервол и доступ
- `PASSWORD_ROOT` или `PASSWORD` — новый пароль пользователя `admin` (через `ChangePassTool`).
- `SSH_PUBLIC_KEY` — публичный SSH-ключ для `admin` (base64 → `config.xml`).
- `PFCTL` — целевое состояние firewall (`YES`/`NO`), которое применяет `reload-iface.sh`.
- `BLOCK_PRIVATE_NETWORKS` — оставляет фильтр `blockpriv` на WAN при значении `YES` (значение по умолчанию — `YES`); при `NO` правило удаляется.
- `BLOCK_BOGON_NETWORKS` — аналогично управляет `blockbogons` на WAN: `YES` оставляет правило (по умолчанию), `NO` — убирает его.


### NAT (outbound)
- `NAT_ENABLE` — включает применение `modules/nat.sh` (значение `YES`).
- `NAT_IF` — логическое имя внешнего интерфейса pfSense, через который выполняется NAT (например, `wan`).
- `NAT_MODE` — режим outbound NAT (`automatic`, `hybrid`, `manual`, `disabled`). Внутри скрипта значения сопоставляются с режимами pfSense (`advanced` используется вместо `manual`).
- `FW_IF` — интерфейс, сеть которого автоматически используется как source при создании правила outbound NAT `context-auto-outbound`, и на котором создаётся правило firewall «allow any → NOT <IP интерфейса>»; значение по умолчанию — `opt1`.

### Управление management-интерфейсом
- `MGMT_ENABLE` — включает (YES) или отключает (NO) применение модуля `mgmt.sh` для выбранного интерфейса.
- `MGMT_IF` — логическое имя интерфейса pfSense (`lan`, `wan`, `optN`), для которого настраиваются правила доступа и убирается шлюз.
- `MGMT_PORT` — перечень TCP-портов (через запятую), из которых формируется алиас `MGMT_PORTS` и разрешается доступ к webGUI/SSH; ICMP добавляется автоматически.
- `MGMT_SRC` — список источников доступа (через запятую). Поддерживаются `iface:any|net`, CIDR/хосты и комбинации `iface:CIDR`; для каждого значения создаются правила Allow ICMP/TCP.
- `MGMT_SRC_DEFAULT_IF` — интерфейс pfSense, к которому будут привязываться источники без явного `iface:` (по умолчанию совпадает с `MGMT_IF`).

### IPsec
- `CONTEXT_IPSEC_ENABLE` — включает применение модуля `ipsec.sh` (по умолчанию `NO`; включите `YES`, если туннели действительно нужны).
- `CONTEXT_IPSEC_TUNNELS` — количество обрабатываемых туннелей; для каждого индекс задаётся автоматически.
- `IPSEC_P1_*` / `IPSEC_P2_*` — глобальные дефолты Phase1/Phase2 (IKE, шифрование, хеш, DH, PFS, время жизни), которые наследуются туннелями, если не переопределены на уровне `CONTEXT_IPSEC_<N>_*`.
- `CONTEXT_IPSEC_<N>_REMOTE`, `PSK`, `LOCALID`, `LOCAL_NET`, `REMOTE_NET` — обязательные параметры туннеля с индексом `N`; дополнительные `P1_*`/`P2_*` ключи можно задавать адресно.
- Модуль пересоздаёт конфигурацию только при изменениях и после обновления вызывает `ipsec_configure()` и `swanctl --initiate`, поэтому контекст можно безопасно запускать повторно для проверки актуальности настроек.

### Автоматизация перезапусков
- `RC_RELOAD_IFACE` — перезапуск WAN-интерфейсов без полного рестарта.

### BGP и FRR
- `BGP_ENABLE` — включает модуль `bgp`.
- `BGP_AS` / `BGP_ROUTER_ID` — номер AS и Router-ID (обязательны при включении).
- `BGP_NEIGHBORS` — соседи в формате `IP,ASN,password` (через пробел/`;`).
- `BGP_NETWORKS_TO_DISTRIBUTE` — сети для анонса (`CIDR,RouteMap`).
- `BGP_RMAP_DEFAULT` — route-map по умолчанию для соседей и сетей.
- `BGP_ADJACENCY_LOG` — включает логирование сессий в FRR.
- `BGP_REDIST_CONNECTED` / `BGP_REDIST_STATIC` / `BGP_REDIST_KERNEL` — контроль перераспределения маршрутов.
- `FRR_DEFAULT_ROUTER_ID` — router-id FRR при отсутствии BGP-настроек.
- `FRR_MASTER_PASSWORD` — пароль vtysh, можно использовать совместно с `FRR_PASSWORD_ENCRYPT` (`on` — хранить в зашифрованном виде).

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
PFCTL="NO"
BLOCK_PRIVATE_NETWORKS="YES"
BLOCK_BOGON_NETWORKS="NO"
PASSWORD="SuperSecret123"
SSH_PUBLIC_KEY="ssh-ed25519 AAAAC3Nz... user@example"

# BGP и FRR
FRR_DEFAULT_ROUTER_ID="192.0.2.1"
BGP_ENABLE="YES"
BGP_AS="65001"
BGP_ROUTER_ID="192.0.2.1"
BGP_RMAP_DEFAULT="ALL"
BGP_NETWORKS_TO_DISTRIBUTE="192.168.10.0/24,ALL"
BGP_NEIGHBORS="198.51.100.2,65002,s3cr3t"

# NAT
NAT_ENABLE="YES"
NAT_MODE="hybrid"
NAT_IF="wan"
NAT_SRC="192.168.10.0/24 192.168.201.0/24"
FW_IF="opt1"

# MGMT
MGMT_ENABLE="YES"
MGMT_IF="lan"
MGMT_PORT="22,443,4443"

```

### Журналы модулей

| Файл | Источник | Что фиксируется |
| --- | --- | --- |
| `/var/log/context.log` | `pfSense/etc/context.d/ContextOnly`, `pfSense/etc/context.d/modules/*` | Последовательность инициализации: монтирование ISO, настройка интерфейсов, DNS, NAT, IPsec, pfctl, обновление пароля, вызовы модулей и вывод `ResizeZfs`.
| `/var/log/context.log` | `pfSense/etc/context.d/modules/bgp` | Дамп переменных, проверка зависимостей FRR, ход инкрементального обновления соседей и сетей, ошибки применения через `vtysh`.
| Пользовательский файл из переменной `LOG` | `pfSense/etc/context.d/modules/ResizeZfs`, `pfSense/etc/context.d/modules/pfctl_off` | Вывод о расширении ZFS и управлении pfctl; по умолчанию перенаправляется в `/dev/null`, при необходимости укажите путь для протоколирования.
