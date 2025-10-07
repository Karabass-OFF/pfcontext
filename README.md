# pfcontext

## Обновление скрипта ContextOnly

1. Скопируйте файл `pfSense/etc/context.d/ContextOnly` из этого репозитория на устройство pfSense по SSH или через `scp`:
   ```sh
   scp pfSense/etc/context.d/ContextOnly root@<pfSense-IP>:/etc/context.d/ContextOnly
   ```
2. На устройстве pfSense сделайте файл исполняемым, если он потерял права после копирования:
   ```sh
   chmod +x /etc/context.d/ContextOnly
   ```
3. При следующем запуске службы контекста (`/etc/rc.d/context onestart`) изменения будут считаны именно из `/etc/context.d/ContextOnly`.

> **Важно.** Все правки сохраняются в файле `pfSense/etc/context.d/ContextOnly` внутри репозитория. При деплое используйте именно его, файл `pfSense/etc/context.d/old/ContextOnly` оставлен только для справки.
