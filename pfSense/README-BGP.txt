# 📘 README – BGP Context Script для pfSense (FRR) + OpenNebula

## Назначение
Этот скрипт автоматически настраивает **BGP в pfSense** с помощью **FRR** (Free Range Routing), используя переменные контекста OpenNebula.  
Он:
- Сохраняет конфигурацию в `/conf/config.xml` через PHP API pfSense.
- Применяет изменения в живой конфигурации FRR через `vtysh`.
- Отслеживает изменения входных переменных и применяет только новые настройки (инкрементально).

---

## ⚙️ Предварительные условия
1. Установлен пакет **FRR** (`frr9` или `pfSense-pkg-frr`).
2. Доступна консольная утилита **php** (`/usr/local/bin/php`).
3. Доступен **vtysh** (`/usr/local/bin/vtysh`) для применения настроек в живой системе.
4. Контекстная служба уже смонтировала диск и экспортировала переменные (скрипт не выполняет `mount`).
   - При ручном запуске можно смонтировать диск самостоятельно и выполнить `.` `/mnt/context/context.sh` до вызова модуля.

---

## 📂 Основные переменные контекста
Все переменные могут быть заданы через `context.sh`.

| Переменная | Назначение | Пример |
|------------|------------|---------|
| `BGP_ENABLE` | Включение/выключение модуля | `yes` |
| `BGP_AS` | Локальный ASN | `65001` |
| `BGP_ROUTER_ID` | Router ID | `192.0.2.1` |
| `BGP_NEIGHBORS` | Соседи BGP: `IP,ASN,Password` (через пробел/;) | `10.0.0.1,65002,secret 10.0.0.2,65003,secret` |
| `BGP_RMAP_DEFAULT` | Route-map по умолчанию | `ALL` |
| `BGP_REDIST_CONNECTED` | Redistribute connected | `yes/no` |
| `BGP_REDIST_STATIC` | Redistribute static | `yes/no` |
| `BGP_REDIST_KERNEL` | Redistribute kernel | `yes/no` |
| `BGP_ADJACENCY_LOG` | Логировать соседство | `on/off` |
| `BGP_NETWORKS_TO_DISTRIBUTE` | Сети для анонса: `prefix,route-map` | `192.168.1.0/24,ALL 10.0.0.0/16,ALL` |

---

## Логика работы
1. Проверяет наличие FRR и PHP.
2. Использует переменные, которые загрузил основной модуль контекста (`ContextOnly`).
   - При ручной отладке можно заранее загрузить `context.sh` в окружение.
3. Считает **хэш от переменных** (ASN, Router ID, соседи, сети).
   - Если изменений нет → завершает работу.
4. Формирует PHP-скрипт и обновляет `/conf/config.xml`.
5. Применяет изменения через **vtysh**:
   - При смене ASN выполняется **полный reset**.
   - При изменении сетей/соседей → выполняется **инкрементальное обновление** (diff).
6. Сохраняет состояние в `/var/run/context-bgp.*`.

---

## 📑 Логи и файлы состояния
- Лог: `/var/log/context-bgp.log` (по умолчанию `/dev/null`).
- Хэш состояния: `/var/run/context-bgp.hash`.
- Списки:
  - Сети: `/var/run/context-bgp.nets`.
  - Router ID: `/var/run/context-bgp.routerid`.
  - Соседи: `/var/run/context-bgp.neigh`.

---

## ▶️ Запуск
Скрипт можно запускать вручную или через **context service**:

```sh
sh /usr/local/etc/context.d/bgp
