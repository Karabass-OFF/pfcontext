# BGP (FRR)

## Назначение
Сценарий `/etc/context.d/bgp` формирует конфигурацию FRR/BGP на основе переменных контекста, синхронизирует параметры с `config.xml` и применяет их через `vtysh`. Поддерживает как полное пересоздание `router bgp`, так и инкрементальный режим.

## Схема запуска
1. Запускается из `ContextOnly` после настройки сетевых интерфейсов.
2. Проверяет наличие пакета `frr9`/`pfSense-pkg-frr` и CLI PHP.
3. Генерирует `vtysh.conf`, если он отсутствует, через PHP-хук `frr_generate_config` и перезапускает службу FRR.
4. Собирает подпись из переменных контекста и сравнивает с предыдущей (`/var/run/context-bgp.hash`). При отсутствии изменений завершает работу.
5. Обновляет разделы `installedpackages` в `config.xml` (глобальные настройки FRR, route-map, BGP, соседи, сети).
6. При необходимости применяет изменения в running-config через `vtysh`: либо пересоздаёт `router bgp`, либо синхронизирует сети/соседей, Router-ID и пароли.
7. Сохраняет вспомогательные файлы состояния (`.nets`, `.routerid`, `.neigh`) для последующих сравнений.

## Переменные контекста
| Переменная | Назначение |
|------------|------------|
| `BGP_ENABLE` | `on` для включения модуля. Любое другое значение прерывает выполнение. |
| `BGP_AS` | Номер автономной системы (обязателен при `BGP_ENABLE=on`). |
| `BGP_ROUTER_ID` | IPv4 Router ID. Используется и как значение `FRR_DEFAULT_ROUTER_ID`, если не задано явно. |
| `BGP_RMAP_DEFAULT` | Имя базового route-map (по умолчанию `ALL`). |
| `BGP_NEIGHBORS` | Список соседей через пробел: `IP,ASN[,PASSWORD]`. Пароли применяются с типом `both-bidir`. |
| `BGP_NETWORKS_TO_DISTRIBUTE` | Список сетей `prefix,route-map`. Если `route-map` опущен, используется `BGP_RMAP_DEFAULT`. |
| `BGP_REDIST_CONNECTED`, `BGP_REDIST_STATIC`, `BGP_REDIST_KERNEL` | Включение соответствующей редистрибуции (`on`/`no`). |
| `BGP_ADJACENCY_LOG` | Управление `bgp log-neighbor-changes`. |
| `FRR_ENABLE` | Переключатель глобального пакета FRR (по умолчанию `on`). |
| `FRR_DEFAULT_ROUTER_ID` | Явное значение Router ID для раздела `frr`. |
| `FRR_MASTER_PASSWORD` | Пароль для веб-интерфейса FRR. Хранится в `config.xml` (значение хэшируется при сравнении). |
| `FRR_PASSWORD_ENCRYPT` | Флаг шифрования (`on` / пусто). |

## Примеры логов
```
2025-10-08 18:20:28 [context] BGP: BGP_ENABLE=on
2025-10-08 18:20:28 [context] BGP: BGP_AS=65017
2025-10-08 18:20:28 [context] BGP: BGP_ROUTER_ID=172.20.12.43
2025-10-08 18:21:58 [context] BGP: vtysh.conf not found, generating via PHP
2025-10-08 18:21:58 [context] BGP: FRR restarted after generating vtysh.conf
2025-10-08 18:21:58 [context] BGP: Added network 91.185.11.168/29 (map ALL)
```
Логи пишутся в `/var/log/context-bgp.log`. При неизменившемся входе выводится `No changes in context variables, skipping execution`.

## Порядок установки и проверки
1. Скопируйте сценарий в `/etc/context.d/` и выдать права: `chmod +x /etc/context.d/bgp`.
2. Убедитесь, что установлен пакет `pfSense-pkg-frr` (`pkg info -x frr`).
3. Выполните `service context onestart` или `/etc/context.d/bgp` вручную из оболочки root (после загрузки переменных контекста).
4. После выполнения проверьте `/var/log/context-bgp.log` на строки `Config.xml updated` и `BGP full reset...`/`incremental sync`.
5. Для валидации используйте `vtysh -c 'show running-config'` и сравните с ожиданиями по соседям и сетям.
