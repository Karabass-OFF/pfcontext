# pfSense Context Automation for OpenNebula

## Назначение проекта

Автоматизация **первичной настройки виртуальной машины pfSense**, развёрнутой в **OpenNebula**.
Скрипты читают файл `context.sh` из виртуального CD-ROM и на основании переданных переменных:

* обновляют `config.xml`,
* настраивают сетевые интерфейсы,
* активируют службы pfSense,
* конфигурируют FRR/BGP.

Это обеспечивает полностью готовый к работе маршрутизатор **сразу после первого запуска ВМ**, без ручного вмешательства.

---

## Структура репозитория

| Путь                                          | Назначение                                                                                                                                                     |
| --------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pfSense/INSTALL`                             | Пошаговая инструкция по развёртыванию скриптов: копирование, установка зависимостей, применение патча, установка FRR, перезагрузка.                            |
| `pfSense/tmp/rc.initial.patch`                | Добавляет вызовы `ResizeZfs` и `ContextOnly` на ранней стадии загрузки; предотвращает повторный запуск в течение первых 3 минут аптайма.                       |
| `pfSense/etc/context.d/ContextOnly`           | Основной модуль. Монтирует CD-ROM, читает `context.sh`, обновляет `config.xml`, применяет сетевые и системные настройки, управляет службами и паролем `admin`. |
| `pfSense/etc/context.d/firewall/`             | Модуль управления NAT, DNAT и межсетевыми правилами на основании переменных контекста; синхронизирует alias-группы и применяет конфигурацию через pfctl. |
| `pfSense/etc/context.d/bgp`                   | Модуль настройки FRR/BGP. Формирует и применяет конфигурацию на основе переменных контекста, ведёт лог и поддерживает инкрементальные обновления.              |
| `pfSense/etc/context.d/ResizeZfs`             | Расширяет ZFS-раздел/пул при увеличении виртуального диска; ведёт журнал операций.                                                                             |
| `pfSense/etc/context.d/pfctl_off`             | Проверяет по PID-файлу, нужно ли временно отключить firewall (pfctl).                                                                                          |
| `pfSense/etc/devd/context.conf`               | Правила devd для автоматического запуска контекстных модулей при событиях (CD-ROM, resize, интерфейсы).                                                        |
| `pfSense/etc/cron.d/context`                  | Планировщик, ежеминутно вызывающий `pfctl_off`.                                                                                                                |
| `pfSense/etc/phpshellsessions/ChangePassTool` | PHP-скрипт pfSense для смены пароля пользователя `admin`.                                                                                                      |

---

## Последовательность выполнения и взаимодействие модулей

1. **Ранняя загрузка pfSense**

   * Патч `rc.initial` запускает `ResizeZfs` и `ContextOnly` один раз в первые 180 секунд.
   * Файл `/var/run/contextallrun_started` предотвращает повторный запуск.

2. **Аппаратные события (devd)**

   * `ContextOnly` вызывается при монтировании CD-ROM.
   * `ResizeZfs` при изменении размера диска.
   * Изменения сетевых интерфейсов записываются в `/etc/context.d/net.pid`.

3. **Модуль `ContextOnly`**

   * Монтирует CD-ROM `/dev/cd0` → `/mnt/context`.
   * Читает `context.sh`, делает резервную копию `config.xml`.
   * Настраивает интерфейсы (LAN/WAN/OPT), IP/маски/шлюзы, DNS, hostname.
   * Управляет `pfctl`, `RC_RELOAD_*`, паролем `admin`, SSH-ключами.
   * Запускает модуль `firewall`, затем `bgp`, размонтирует CD-ROM.

4. **Модуль `firewall`**

   * Загружает переменные `context.sh` и синхронизирует alias-группы `CTX_ALLOW_NETS` и `CTX_BLOCK_NETS`.
   * Обновляет outbound NAT (сети и отдельные хосты), правила DNAT и transit (forward) на интерфейсах.
   * Вызывает `filter_configure()` и проверяет `/tmp/rules.debug` через `pfctl -nf`, затем активирует правила `pfctl -f`.

5. **Модуль `bgp`**

   * Проверяет наличие FRR.
   * Генерирует `config.xml` и применяет конфигурацию через PHP и `vtysh`.
   * Хранит контрольные суммы и состояния в `/var/run/context-bgp.*`.

6. **`ResizeZfs`**

   * Автоматически расширяет ZFS-раздел при наличии свободного места.
   * Используется и при загрузке, и при событиях devd.

7. **Контроль firewall**

   * `cron` каждую минуту вызывает `pfctl_off`.
   * Если существует `/var/run/pfctlcontext.pid`, `pfctl` отключается.

> 💡 Альтернатива без патча: добавить строку
> `<earlyshellcmd>/etc/context.d/ContextOnly </earlyshellcmd>`
> в `config.xml`. Однако поставка по умолчанию использует патч `rc.initial`.

---

## Процесс установки

1. **Копирование файлов**

   ```bash
   scp -r ./ root@pfSense:/
   ```

2. **Установка зависимостей**

   ```bash
   pkg install -y xmlstarlet pfSense-pkg-frr
   ```

   или

   ```bash
   pkg install -y xmlstarlet frr9
   ```

3. **Применение патча**

   ```bash
   patch --dry-run < /tmp/rc.initial.patch
   patch < /tmp/rc.initial.patch
   ```

4. **Очистка логов и резервных файлов** (опционально).

5. **Перезагрузка pfSense**:

   ```bash
   reboot
   ```

---

## Переменные контекста

Все параметры задаются в `context.sh` (Bash-совместимый формат).
Поддерживаются оба префикса: `ETHx_*` и `ETHERNETx_*`.

### 🔹 Сетевые параметры

| Переменная     | Назначение                              |
| -------------- | --------------------------------------- |
| `ETHx_MAC`     | MAC-адрес интерфейса для сопоставления. |
| `ETHx_TYPE`    | Роль интерфейса: `lan`, `wan`, `optN`.  |
| `ETHx_IP`      | IPv4-адрес интерфейса.                  |
| `ETHx_MASK`    | Маска подсети.                          |
| `ETHx_GATEWAY` | Шлюз по умолчанию (для WAN).            |
| `ETHx_DNS`     | DNS-серверы (через пробел).             |

> Если тип не указан — приватные сети назначаются как `lan`, публичные — как `wan`.

---

### 🔹 Сервисные параметры

| Переменная        | Назначение                                                 |
| ----------------- | ---------------------------------------------------------- |
| `PFCTL`           | Управление firewall (`off` / `on`).                        |
| `RC_RELOAD_ALL`   | Полная перезагрузка сервисов после изменения `config.xml`. |
| `RC_RELOAD_IFACE` | Перезапуск WAN-интерфейсов без полной перезагрузки.        |
| `PASSWORD`        | Новый пароль `admin`.                                      |
| `SSH_PUBLIC_KEY`  | Добавляется в `/root/.ssh/authorized_keys`.                |

---

### 🔹 Параметры BGP и FRR

| Переменная                   | Назначение                       |
| ---------------------------- | -------------------------------- |
| `BGP_ENABLE`                 | Включает модуль BGP.             |
| `BGP_AS`, `BGP_ROUTER_ID`    | Номер AS и router-id.            |
| `BGP_NEIGHBORS`              | Соседи (IP,ASN,password).        |
| `BGP_NETWORKS_TO_DISTRIBUTE` | Сети для анонса (CIDR,RouteMap). |
| `BGP_RMAP_DEFAULT`           | Route-map по умолчанию.          |
| `FRR_ENABLE`                 | Включение FRR.                   |
| `FRR_DEFAULT_ROUTER_ID`      | Router-id FRR.                   |

### 🔹 Параметры firewall

| Переменная                    | Назначение                                                                                 |
| ----------------------------- | ------------------------------------------------------------------------------------------ |
| `FIREWALL_ENABLE`             | Включает модуль firewall (`on`/`off`).                                                     |
| `FIREWALL_PFCTL`              | Управление применением правил через `pfctl` (`on` — активировать, `off` — только записать).|
| `FIREWALL_NAT_OUT_IF`         | Интерфейс исходящего NAT.                                                                  |
| `FIREWALL_NAT_NETS`           | Сети (через пробел) для автоматического outbound NAT.                                      |
| `FIREWALL_NAT_HOSTS`          | Отдельные IP-адреса для NAT.                                                               |
| `FIREWALL_PORT_FORWARD_LIST`  | Список DNAT-правил `iface:proto:ext_port:int_ip:int_port`.                                 |
| `FIREWALL_FORWARD_ALLOW`      | Интерфейсы, между которыми разрешён транзит (например `lan1,lan2`).                        |
| `FIREWALL_ALLOW_NETS`         | Список сетей для alias `CTX_ALLOW_NETS`.                                                    |
| `FIREWALL_BLOCK_NETS`         | Список сетей/адресов для alias `CTX_BLOCK_NETS`.                                            |
| `FIREWALL_DEFAULT_FORWARD`    | Политика по умолчанию (`allow` или `deny`) для указанных интерфейсов.                       |
| `FIREWALL_LOG`                | Управление логированием модуля (`on`/`off`).                                                |
| `FIREWALL_RELOAD`             | `auto` — сразу применять через `pfctl`, `manual` — только сохранить конфигурацию.          |

---

### 🔹 Системные параметры

| Переменная     | Назначение                                                     |
| -------------- | -------------------------------------------------------------- |
| `SET_HOSTNAME` | Имя хоста pfSense.                                             |
| `CONTEXT_*`    | Внутренние служебные переменные (не изменяются пользователем). |

---

## Пример `context.sh`

```bash
# WAN
ETH0_MAC="00:50:56:aa:bb:01"
ETH0_TYPE="wan"
ETH0_IP="203.0.113.10"
ETH0_MASK="255.255.255.252"
ETH0_GATEWAY="203.0.113.9"
ETH0_DNS="8.8.8.8 1.1.1.1"

# LAN
ETH1_MAC="00:50:56:aa:bb:02"
ETH1_TYPE="lan"
ETH1_IP="192.168.10.1"
ETH1_MASK="255.255.255.0"
ETH1_DNS="192.168.10.1"

# System
SET_HOSTNAME="pfsense-demo"
PFCTL="off"
RC_RELOAD_ALL="on"
PASSWORD="SuperSecret123"
SSH_PUBLIC_KEY="ssh-ed25519 AAAAC3Nz... user@example"

# BGP / FRR
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

---

## Отладка и эксплуатация

| Цель                       | Действие                                                  |
| -------------------------- | --------------------------------------------------------- |
| Основной лог               | `/var/log/context.log` — события ContextOnly.             |
| Лог BGP                    | `/var/log/context-bgp.log` — операции FRR.                |
| Повторный запуск контекста | `/etc/context.d/ContextOnly` вручную.                     |
| Проверка пакетов           | `pkg info xmlstarlet` / `pkg info frr9`.                  |
| Проверка zpool             | `zpool list pfSense` — убедиться, что ResizeZfs применён. |

> Если `PFCTL=off`, убедитесь в наличии `/var/run/pfctlcontext.pid` — без него cron-задача не вмешивается.

---

## Итог

Этот набор скриптов обеспечивает **полную автоматизацию конфигурации pfSense** в среде OpenNebula:
сетевая настройка, FRR/BGP, SSH-доступ, пароли и DNS — всё применяется автоматически при первом старте.
Документ предназначен как **техническое руководство для администраторов**.
