# pfcontext

Набор сценариев автоматизации для pfSense, адаптированных под контекст OpenNebula. Репозиторий содержит основной модуль `ContextOnly`, вспомогательные обработчики сетевой безопасности, FRR/BGP, а также скрипт расширения ZFS.

## Структура

| Путь | Назначение | Документация |
| ---- | ---------- | ------------- |
| `pfSense/etc/context.d/ContextOnly` | Основной обработчик контекста OpenNebula для pfSense. Создаёт интерфейсы, настраивает DNS, пароль администратора, управляет pfctl и вызывает дополнительные модули. | [Readme$context](pfSense/Readme$context.md) |
| `pfSense/etc/context.d/bgp` | Генерирует конфигурацию FRR/BGP из переменных контекста и синхронизирует её с `config.xml` и running-config. | [Readme$bgp](pfSense/Readme$bgp.md) |
| `pfSense/etc/context.d/ResizeZfs` | Расширяет пул `pfSense` до доступного размера тома. | [Readme$zfs](pfSense/Readme$zfs.md) |
| `pfSense/etc/context.d/pfctl_off` | Отключает pf при необходимости, когда контекст задаёт `PFCTL=off`. | [Readme$pfctl](pfSense/Readme$pfctl.md) |
| `pfSense/etc/context.d/frr` | Штатный rc-скрипт pfSense для запуска демонов FRR. | [Readme$frr](pfSense/Readme$frr.md) |

## Базовая установка

1. Скопируйте нужные сценарии на хост pfSense:
   ```sh
   scp -r pfSense/etc/context.d/ root@<pfSense-IP>:/etc/context.d/
   ```
2. Проверьте права:
   ```sh
   chmod +x /etc/context.d/*
   ```
3. Убедитесь, что служба контекста включена в `config.xml`:
   ```xml
   <earlyshellcmd>/etc/rc.d/context onestart</earlyshellcmd>
   ```
4. Запустите контекст вручную для проверки:
   ```sh
   /etc/rc.d/context onestart
   ```

## Проверка

* Основной лог контекста: `/tmp/context.log`.
* Лог BGP: `/var/log/context-bgp.log`.
* Для отладки расширения ZFS временно переключите `LOG` в `ResizeZfs` на `/tmp/context.log`.

Подробные инструкции по каждому модулю приведены в соответствующих файлах README.
