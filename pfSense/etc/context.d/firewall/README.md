# Context Firewall Module for pfSense 2.8 (OpenNebula)

`firewall.sh` — дополнительный модуль контекста, который выполняется из `ContextOnly` после настройки интерфейсов. Скрипт управляет только теми элементами `config.xml`, чьи описания начинаются с префикса `ContextFW:`; все остальные правила, созданные через GUI/VPN/DHCP, остаются неизменными.

## Структура скрипта
Сценарий разбит на логические блоки с явными заголовками:

1. **Entry point** — проверка зависимостей (`pfctl`, `php`, `xml`, `pfSsh.php`), установка блокировки `/var/run/context-firewall.lock` (TTL 10 минут) и подготовка окружения.
2. **Load variables** — загрузка переменных из `context.sh`, проверка флагов `FIREWALL_ENABLE` и `FIREWALL_PFCTL`, подготовка рабочей копии `config.xml` (используется backup, созданный `ContextOnly`).
3. **Common functions** — журналирование (`/var/log/context-firewall.log`), резервное копирование (`/cf/conf/backup/config.xml.firewall.*`), откат, вычисление хэшей состояния, вспомогательные утилиты.
4. **NAT / outbound NAT** — подготовка данных для исходящего NAT и правил `nonat`.
5. **DNAT / Port Forwards** — парсинг `FIREWALL_PORT_FORWARD_LIST`, поддержка флага `assoc_rule` и связанных правил фильтрации.
6. **Forward rules** — генерация правил `pass`/`block` по спискам интерфейсов, IP-адресов и сетей блокировки.
7. **Validation & Apply** — применение изменений в рабочей копии, генерация `/tmp/rules.debug` через `php /etc/rc.filter_configure_sync`, проверка `pfctl -nf`, атомарный `mv` в `/cf/conf/config.xml`, запуск `pfSsh.php playback reloadfilter` (или пропуск в режиме manual), управление состоянием (`/var/run/context-firewall.state`) и откат при ошибках.

## Контекстные переменные
Пример содержимого `context.sh` для активации модуля:

```sh
FIREWALL_ENABLE="on"
FIREWALL_DEBUG="off"
FIREWALL_PFCTL="on"
FIREWALL_RELOAD="auto"        # auto | manual
FIREWALL_LOG="on"
FIREWALL_DEFAULT_FORWARD="deny"

FIREWALL_NAT_OUT_IF="vtnet0"
FIREWALL_NAT_NETS="192.168.0.0/16 10.0.0.0/8"
FIREWALL_NAT_HOSTS="192.168.10.5 192.168.10.6"
FIREWALL_NAT_ALLOW_NETS="192.168.0.0/16"

FIREWALL_PORT_FORWARD_LIST="if=wan,proto=tcp,ext_addr=wanaddress,ext_port=443,int_ip=192.168.10.2,int_port=443,descr=HTTPS,assoc_rule=pass"

FIREWALL_FORWARD_ALLOW_IF="lan,opt1"
FIREWALL_FORWARD_ALLOW_IP="192.168.10.5,10.0.0.8"
FIREWALL_BLOCK_NETS="203.0.113.0/24"
```

## Пример результата в `config.xml`
После успешного применения модуль добавляет собственные элементы:

```xml
<nat>
  <outbound>
    <mode>hybrid</mode>
    <rule>
      <interface>vtnet0</interface>
      <source>
        <network>192.168.0.0/16</network>
      </source>
      <destination>
        <any/>
      </destination>
      <descr>ContextFW:NAT 192.168.0.0/16 via vtnet0</descr>
    </rule>
    <!-- ... -->
  </outbound>
  <rule>
    <interface>wan</interface>
    <protocol>tcp</protocol>
    <destination>
      <network>wanaddress</network>
      <port>443</port>
    </destination>
    <target>192.168.10.2</target>
    <local-port>443</local-port>
    <descr>ContextFW:PF HTTPS</descr>
  </rule>
</nat>
<filter>
  <rule>
    <type>pass</type>
    <interface>lan</interface>
    <source>
      <network>lan</network>
    </source>
    <destination>
      <any/>
    </destination>
    <descr>ContextFW:Forward allow lan</descr>
  </rule>
  <rule>
    <type>block</type>
    <interface>wan</interface>
    <source>
      <network>203.0.113.0/24</network>
    </source>
    <destination>
      <any/>
    </destination>
    <descr>ContextFW:Block 203.0.113.0/24</descr>
  </rule>
  <!-- ... -->
</filter>
```

## Режим manual
Если `FIREWALL_RELOAD="manual"`, модуль формирует и валидирует конфигурацию, но не запускает `pfSsh.php playback reloadfilter` и `/etc/rc.reload_all`. Примените изменения вручную:

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
