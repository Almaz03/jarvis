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
- `AUTH0_OWNER_SUB` — точный Auth0 `user_id` единственного владельца, например
  `auth0|...`. Пока secret отсутствует, MCP/Caddy profile не запускается и
  существующий Telegram ingress продолжает работать.

Ни одно значение не отправляйте в чат и не добавляйте в Git.

После добавления secrets создайте repository variable `DEPLOY_ENABLED=true`
в `Settings → Secrets and variables → Actions → Variables`. Первый запуск
можно сделать через `Actions → CI and deploy → Run workflow` или новым push.

## Требования к VPS

- Linux с Docker Engine и Compose plugin.
- Deploy-пользователь может запускать `docker compose`.
- Его public SSH key находится в `~/.ssh/authorized_keys`.
- Исходящие HTTPS-соединения к `api.telegram.org`, Auth0 JWKS и callback ChatGPT разрешены.
- Входящие TCP 80/443 разрешены; DNS `jarvis.akalmaz.tech` указывает на VPS.

Workflow устанавливает release в `~/jarvis/releases/<git-sha>`, хранит
секретный `.env` с правами `0600`, а SQLite state — в `~/jarvis/state`.
Telegram/MCP контейнеры запускаются без root и с read-only filesystem. Только
Caddy публикует 80/443 и имеет capability `NET_BIND_SERVICE`; TLS state хранится
в named volumes.

## Текущий live scope

Worker использует Telegram `getUpdates`, принимает только текст из заранее
заданного личного чата владельца и отвечает на `/start` и `/status`.
Остальные сообщения сохраняются в durable inbox для следующего этапа.

Это ещё не доказывает ответ существующего dot. После включения MCP нужно отдельно
подключить endpoint к нужному dot, создать подписку и подтвердить сквозной nonce.
