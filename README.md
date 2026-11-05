# Telegram ↔ существующий dot: локальный тестовый стенд

**Статус: live Telegram ingress работает; защищённый MCP/Events сервер реализован, но ещё не включён и не подключён к dot.** В стенде нет отдельной LLM, OpenAI API-биллинга или голосового канала. Live worker принимает сообщения одного заранее заданного владельца.

Цель следующего этапа — текстовый путь `Telegram → bridge → MCP Events → этот существующий dot → reply tool → Telegram`, а не новый агент с другим контекстом. MCP Events — документированный кандидат для событий в подписанном чате dot; это не доказательство готового нативного Telegram-канала. Реальный end-to-end ещё не проверен.

## Быстрый запуск без секретов

Нужен Python 3.12+. Для полного набора тестов установите зависимости из
`requirements.txt`; offline demo по-прежнему не делает сетевых запросов.

```sh
cd telegram-dot-stand
python3 -m pip install -r requirements.txt
python3 -m unittest discover -s tests -v
python3 -m stand demo
```

`demo` создаёт временную БД с вымышленными ID `424242`, принимает один update, отсекает дубль, показывает **неотправленный** event envelope и **неотправленный** ответ, проверяет дубль после рестарта, удаляет временную БД. Ответ — заранее заданное эхо nonce, не ответ модели.

Для сохранённого локального inbox:

```sh
set -a
. ./env.example
set +a
python3 -m stand ingest < fixtures/owner-update.jsonl
# Второй запуск с той же БД должен вернуть только duplicates.
python3 -m stand ingest < fixtures/owner-update.jsonl
```

Не подставляйте реальные токены или пользовательскую переписку: значения в примере синтетические и **не подтверждают принадлежность аккаунта**.

Опциональный локальный HTTP mock:

```sh
python3 -m stand serve --port 8787
# В другом локальном терминале, после загрузки env.example:
curl -sS -H 'X-Stand-Local-Test: 1' http://127.0.0.1:8787/health
head -n 1 fixtures/owner-update.jsonl | curl -sS \
  -H 'X-Stand-Local-Test: 1' -H 'Content-Type: application/json' \
  --data-binary @- http://127.0.0.1:8787/mock/updates
```

Сервер привязан только к `127.0.0.1`; отсутствуют `/mcp` и реальный Telegram webhook. Заголовок `X-Stand-Local-Test` — защита от случайного browser/CSRF-вызова, **не аутентификация**. Любой локальный процесс может имитировать fixture. Не пробрасывать порт, не ставить tunnel/proxy и не использовать в production.

Dockerfile — опциональная упаковка, не deployment:

```sh
docker build -t telegram-dot-stand .
docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m telegram-dot-stand
```

Образ не имеет опубликованных портов и запускает только offline demo. Docker build требует скачивания базового образа. В целевом cloud-окружении сборка и запуск с `--network none --read-only` проверены; точные результаты записаны в `VERIFICATION.md`.

## Live Telegram ingress и CI/CD

Live worker использует `getUpdates` и фиксированный официальный endpoint
`api.telegram.org`. Он не принимает произвольный API base URL и не логирует
token, Telegram IDs или текст сообщений.

Deployment выполняет [GitHub Actions workflow](.github/workflows/ci-deploy.yml);
настройка secrets и VPS описана в [DEPLOYMENT.md](DEPLOYMENT.md). По умолчанию
deploy job выключен переменной `DEPLOY_ENABLED`.

## Что реально реализовано

- Раздельная allowlist `from.id` и private `chat.id`, строгие числовые типы; группы, боты, edits, channel/business posts, via-bot и forwards отклоняются.
- SQLite-транзакция сохраняет принятый update вместе с opaque `message_ref` и стабильным `event_id`. Дубликаты после рестарта и updates вне порядка безопасны. Отклонённые updates не сохраняются; polling offset здесь отсутствует.
- Текст хранится как **untrusted data**; команды/URL не исполняются. Пересланные сообщения пока полностью отвергаются. В event preview только opaque ref, без текста; `read_message` возвращает текст явно как untrusted.
- Live tool `reply_to_telegram_message(message_ref, text, idempotency_key)` проверяет Auth0 principal/scopes; recipient берётся из сохранённого inbox. Передать произвольный `chat_id` нельзя. Дубликат подавляется, конфликт ключа отклоняется, неопределённая отправка не повторяется вслепую.
- Фиктивный `MockPrincipal` проверяет scope/expiry/confirmed для unit-тестов. Это **не проверенная identity mapping и не OAuth**. Смена owner IDs на уже существующей БД запрещена.
- У БД права `0600`, у каталога `0700`; симлинки запрещены. Локальные исходные тексты в БД не зашифрованы; это fixture storage, не безопасное хранилище production.
- Offline-команды не имеют outbound HTTP-клиента. Отдельный live worker обращается только к фиксированным методам Telegram Bot API; произвольные callbacks по-прежнему запрещены.
- Логи содержат только allowlist статусов/opaque refs, не тексты, chat/user IDs, токены, URL. Добавлен redactor как дополнительная защита, не замена запрету логирования секретов.
- `stand/mcp_live.py` реализует stateless MCP `2026-07-28`, Auth0 JWT verification, exact owner `sub`, tools и Events lifecycle. Подписки/очередь устойчивы в SQLite; callback проходит HTTPS/DNS/TLS pinning, challenge и Standard Webhooks; transient failures имеют bounded retry, 410/413 не повторяются. Event `cursor=null`; replay не заявлен.
- Caddy публикует `https://jarvis.akalmaz.tech/mcp` и автоматически получает TLS-сертификат. MCP/Caddy запускаются отдельным compose profile только при наличии `AUTH0_OWNER_SUB` в GitHub Environment.

Статусы не смешиваются: `local_inbox_only`, `event_preview_not_delivered`, `dry_run_not_sent` не означают `event accepted`, `dot processed` или `Telegram confirmed`.

## Что осталось до реального теста

1. Создать/выбрать ровно одного Auth0 пользователя-владельца и добавить его точный `user_id` (`sub`) как production secret `AUTH0_OWNER_SUB`. Первый вошедший пользователь автоматически владельцем не становится.
2. После успешного deploy проверить public metadata/health и подключить `https://jarvis.akalmaz.tech/mcp` как custom plugin к нужному dot.
3. Создать одну Events-подписку с узкой инструкцией и выполнить тест несекретным nonce: Telegram → event → этот dot → reply tool → тот же Telegram chat.
4. После подтверждения roundtrip проверить unsubscribe/reconnect/retry. Голос рассматривать только после текстового E2E; Telegram Bot API не принимает обычные звонки.

## Источники и границы исследования

Проверено 29.10.2026. Условия доступа/account/workspace нужно проверить на целевом аккаунте, они не установлены этим mock.

- [OpenAI MCP Events](https://developers.openai.com/plugins/build/mcp-events): поддержка dots, MCP2, event/subscription/callback contract, подпись и доставка.
- [MCP server](https://developers.openai.com/plugins/build/mcp-server) и [OAuth](https://developers.openai.com/plugins/build/auth): сервер, tools и аутентификация.
- [Подключение custom plugin](https://developers.openai.com/plugins/deploy/connect-chatgpt) и [Security & privacy](https://developers.openai.com/plugins/guides/security-privacy).
- [Telegram getUpdates](https://core.telegram.org/bots/api#getupdates), [setWebhook](https://core.telegram.org/bots/api#setwebhook), [sendMessage](https://core.telegram.org/bots/api#sendmessage), [deep linking](https://core.telegram.org/bots/features#deep-linking).

Реализация на Python 3.12 использует Starlette/Uvicorn, PyJWT и cryptography для live MCP слоя; версии зафиксированы в `requirements.txt`.

## Файлы

`stand/core.py` — inbox и фильтры. `stand/telegram_live.py` — Telegram transport. `stand/mcp_live.py` — Auth0/MCP/tools/events. `compose.yaml` и `Caddyfile` — live deployment. `tests/` — offline проверки. `VERIFICATION.md` — результаты запусков.
