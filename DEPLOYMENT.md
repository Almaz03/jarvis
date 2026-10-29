# Push-to-deploy

При каждом push в `main` workflow сначала запускает тесты и offline Docker
smoke-test. Deployment выполняется только если repository variable
`DEPLOY_ENABLED` равна `true`.

## GitHub Environment

Создайте environment `production` в
`Settings → Environments → New environment`. Добавьте в него secrets:

- `VPS_HOST` — hostname или IP сервера.
- `VPS_PORT` — SSH-порт, обычно `22`.
- `VPS_USER` — отдельный непривилегированный deploy-пользователь.
- `VPS_SSH_PRIVATE_KEY` — отдельный private key только для deployment.
- `VPS_KNOWN_HOSTS` — заранее проверенная строка host key сервера. Не
  генерируйте её автоматически внутри workflow.
- `TELEGRAM_BOT_TOKEN` — токен нового бота от BotFather.
- `TELEGRAM_OWNER_USER_ID` — numeric Telegram user ID владельца.
- `TELEGRAM_OWNER_CHAT_ID` — numeric ID личного чата владельца.

Ни одно значение не отправляйте в чат и не добавляйте в Git.

После добавления secrets создайте repository variable `DEPLOY_ENABLED=true`
в `Settings → Secrets and variables → Actions → Variables`. Первый запуск
можно сделать через `Actions → CI and deploy → Run workflow` или новым push.

## Требования к VPS

- Linux с Docker Engine и Compose plugin.
- Deploy-пользователь может запускать `docker compose`.
- Его public SSH key находится в `~/.ssh/authorized_keys`.
- Исходящие HTTPS-соединения к `api.telegram.org` разрешены.

Workflow устанавливает release в `~/jarvis/releases/<git-sha>`, хранит
секретный `.env` с правами `0600`, а SQLite state — в `~/jarvis/state`.
Контейнер запускается без root, с read-only filesystem, без открытых портов и
без дополнительных Linux capabilities.

## Текущий live scope

Worker использует Telegram `getUpdates`, принимает только текст из заранее
заданного личного чата владельца и отвечает на `/start` и `/status`.
Остальные сообщения сохраняются в durable inbox для следующего этапа.

Это ещё не ответ существующего dot. MCP OAuth, Events subscription/callback и
`reply_to_message` live transport будут добавлены отдельным этапом.
