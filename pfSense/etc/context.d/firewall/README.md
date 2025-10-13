# Context Firewall Module for pfSense 2.8 (OpenNebula)

`firewall.sh` — модуль контекста для **pfSense 2.8-RELEASE**, выполняемый из `ContextOnly` после настройки сетевых интерфейсов.  
Скрипт управляет только теми элементами `config.xml`, чьи описания начинаются с префикса `ContextFW:`;  
все остальные правила, созданные вручную (через GUI, VPN, DHCP и т.д.), остаются без изменений.

---

## Структура скрипта

1. **Entry point**  
   Проверка зависимостей (`pfctl`, `php`, `xml`, `pfSsh.php`), установка блокировки `/var/run/context-firewall.lock` (TTL 600 с), подготовка окружения.

2. **Load variables**  
   Загрузка переменных из `/mnt/context/context.sh` (CD-ROM OpenNebula), проверка флагов `FIREWALL_ENABLE` и `FIREWALL_PFCTL`, создание рабочей копии `config.xml` (используется backup от `ContextOnly`).

3. **Common functions**  
   Журналирование (`/var/log/context-firewall.log`), резервное копирование (`/cf/conf/backup/config.xml.firewall.*`), восстановление (`rollback`), хэширование состояния (`/var/run/context-firewall.state`), вспомогательные утилиты.

4. **NAT / Outbound NAT**  
   Формирование правил исходящего NAT и `nonat` на основе переменных `FIREWALL_NAT_*`.

5. **DNAT / Port Forwards**  
   Парсинг `FIREWALL_PORT_FORWARD_LIST`, генерация DNAT-правил и связанных фильтров (`assoc_rule=pass`).

6. **Forward Rules / Filters**  
   Создание `pass` / `block` правил по спискам интерфейсов, IP-адресов и сетей блокировки.

7. **Validation & Apply**  
   Проверка изменений, вызов `php /etc/rc.filter_configure_sync` для генерации `/tmp/rules.debug`, валидация через `pfctl -nf`, атомарное обновление `config.xml`, вызов `pfSsh.php playback reloadfilter` (или пропуск при `manual`), сохранение состояния.

---

## Контекстные переменные (`context.sh`)

Ниже приведён полный список переменных, поддерживаемых модулем, и их описание.  
Все значения читаются из `/mnt/context/context.sh` (CD-ROM OpenNebula).

| Переменная | Возможные значения | Назначение |
|-------------|--------------------|-------------|
| **FIREWALL_ENABLE** | `on` / `off` | Включение или отключение модуля. |
| **FIREWALL_PFCTL** | `on` / `off` | Применять ли изменения через `pfctl`. |
| **FIREWALL_RELOAD** | `auto` / `manual` | Режим перезагрузки после применения. |
| **FIREWALL_DEBUG** | `on` / `off` | Подробный отладочный вывод. |
| **FIREWALL_LOG** | `on` / `off` | Добавлять флаг логирования (`log`) в правила. |
| **FIREWALL_DEFAULT_FORWARD** | `allow` / `deny` | Поведение по умолчанию для входящего трафика. |
| **FIREWALL_NAT_OUT_IF** | имя интерфейса (например, `wan`) | Интерфейс для исходящего NAT. |
| **FIREWALL_NAT_NETS** | список CIDR (через пробел, запятую или `;`) | Сети, для которых создаются NAT-правила. |
| **FIREWALL_NAT_HOSTS** | список IP | Отдельные хосты для исходящего NAT. |
| **FIREWALL_NAT_ALLOW_NETS** | список CIDR | Сети, **исключаемые** из NAT (`nonat`). |
| **FIREWALL_BLOCK_NETS** | список CIDR | Сети, которые блокируются на входе (WAN). |
| **FIREWALL_FORWARD_ALLOW_IF** | список интерфейсов | Разрешить трафик с указанных интерфейсов. |
| **FIREWALL_FORWARD_ALLOW_IP** | список IP | Разрешить трафик с указанных IP-адресов. |
| **FIREWALL_PORT_FORWARD_LIST** | строка с DNAT-записями | Правила проброса портов (см. ниже). |

---

### Формат `FIREWALL_PORT_FORWARD_LIST`

Правила указываются через `;`. Каждое правило — набор пар `ключ=значение`, разделённых запятыми:

```bash
FIREWALL_PORT_FORWARD_LIST="\
if=wan,proto=tcp,ext_addr=wanaddress,ext_port=443,int_ip=192.168.10.2,int_port=443,descr=HTTPS,assoc_rule=pass;\
if=wan,proto=udp,ext_port=1194,int_ip=192.168.10.3,int_port=1194,descr=OpenVPN"
```
---

### Пример context.sh

```bash
# Enable context firewall
FIREWALL_ENABLE="on"
FIREWALL_PFCTL="on"
FIREWALL_RELOAD="auto"
FIREWALL_DEBUG="off"
FIREWALL_LOG="on"
FIREWALL_DEFAULT_FORWARD="deny"

# Outbound NAT
FIREWALL_NAT_OUT_IF="vtnet0"
FIREWALL_NAT_NETS="10.0.0.0/8,192.168.0.0/16"
FIREWALL_NAT_HOSTS="10.0.0.5"
FIREWALL_NAT_ALLOW_NETS="172.16.0.0/12"

# Filtering / forwarding
FIREWALL_FORWARD_ALLOW_IF="lan,opt1"
FIREWALL_FORWARD_ALLOW_IP="10.0.0.8,192.168.10.5"
FIREWALL_BLOCK_NETS="203.0.113.0/24"
```
### Port forwarding

```bash
FIREWALL_PORT_FORWARD_LIST="\
if=wan,proto=tcp,ext_port=443,int_ip=192.168.10.2,int_port=443,descr=HTTPS,assoc_rule=pass;\
if=wan,proto=udp,ext_port=1194,int_ip=192.168.10.3,int_port=1194,descr=OpenVPN"
```
### Режим manual

Если ```FIREWALL_RELOAD="manual"```, модуль готовит и проверяет конфигурацию,
но не выполняет ```pfSsh.php playback reloadfilter``` и ```/etc/rc.reload_all```.
Если ```FIREWALL_RELOAD="manual"```, модуль готовит и проверяет конфигурацию,
но не выполняет ```pfSsh.php playback reloadfilter``` и ```/etc/rc.reload_all```.

Чтобы применить правила вручную:

```sh
/usr/local/sbin/pfSsh.php playback reloadfilter
/etc/rc.reload_all
```
Состояние настроек (`sha256` от нормализованных переменных) хранится в `/var/run/context-firewall.state`. Повторный запуск с теми же параметрами завершится без изменений.

## Дополнительные сведения
- Лог: `/var/log/context-firewall.log` с префиксами `[INFO]`, `[WARN]`, `[ERROR]`, `[DEBUG]`.
- Блокировка: `/var/run/context-firewall.lock` (удаляется автоматически, TTL 600 секунд).
- Резервная копия: `/cf/conf/backup/config.xml.firewall.<timestamp>`; при ошибке проверки выполняется `[rollback]` и восстановление исходного `config.xml`.
- Модуль управляет только правилами `ContextFW:` и не изменяет настройки, созданные через веб-интерфейс, VPN или DHCP.