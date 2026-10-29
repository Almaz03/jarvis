# Telegram ↔ существующий dot: локальный тестовый стенд

**Статус: credential-free mock, НЕ подключение к Telegram или dot.** В стенде нет отдельной LLM, OpenAI API, API-биллинга, OAuth, bot token, регистрации бота, публичного сервера или голосового канала. Реальные сообщения не отправляются. Live-режим отсутствует и отклоняется, даже если попытаться включить его переменной окружения.

Цель следующего этапа — текстовый путь `Telegram → bridge → MCP Events → этот существующий dot → reply tool → Telegram`, а не новый агент с другим контекстом. MCP Events — документированный кандидат для событий в подписанном чате dot; это не доказательство готового нативного Telegram-канала. Реальный end-to-end ещё не проверен.

## Быстрый запуск без секретов

Нужен Python 3.12+; только стандартная библиотека, `pip install` не нужен.

```sh
cd telegram-dot-stand
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

## Что реально реализовано

- Раздельная allowlist `from.id` и private `chat.id`, строгие числовые типы; группы, боты, edits, channel/business posts, via-bot и forwards отклоняются.
- SQLite-транзакция сохраняет принятый update вместе с opaque `message_ref` и стабильным `event_id`. Дубликаты после рестарта и updates вне порядка безопасны. Отклонённые updates не сохраняются; polling offset здесь отсутствует.
- Текст хранится как **untrusted data**; команды/URL не исполняются. Пересланные сообщения пока полностью отвергаются. В event preview только opaque ref, без текста; `read_message` возвращает текст явно как untrusted.
- `reply_to_message(message_ref, text, idempotency_key)` проверяет mock principal/read–reply scopes; recipient берётся из сохранённого inbox. Передать произвольный `chat_id` нельзя. Дубликат ответа подавляется, повтор ключа с другим содержимым — ошибка. Единственный статус ответа: `dry_run_not_sent`.
- Фиктивный `MockPrincipal` проверяет scope/expiry/confirmed для unit-тестов. Это **не проверенная identity mapping и не OAuth**. Смена owner IDs на уже существующей БД запрещена.
- У БД права `0600`, у каталога `0700`; симлинки запрещены. Локальные исходные тексты в БД не зашифрованы; это fixture storage, не безопасное хранилище production.
- Нет outbound HTTP-клиента: любые callbacks, в том числе публичные, запрещены. Это fail-closed заглушка, не реализованная SSRF-защита для live.
- Логи содержат только allowlist статусов/opaque refs, не тексты, chat/user IDs, токены, URL. Добавлен redactor как дополнительная защита, не замена запрету логирования секретов.
- `mcp_contract.py` содержит только локальные fixtures `server/discover`, `events/list` и отказ subscription. **Это не полноценный MCP 2.0 endpoint.** Нет подписки, подписи HMAC, challenge, доставки, retry, refresh, replay или unsubscribe. Event `cursor=null`; replay не заявлен.

Статусы не смешиваются: `local_inbox_only`, `event_preview_not_delivered`, `dry_run_not_sent` не означают `event accepted`, `dot processed` или `Telegram confirmed`.

## Что нужно до реального теста — отдельно и с разрешением

1. Выбрать отдельный coding chat/repo/server/environment, доступный пользователю; перенести проверенный стенд. Ничего не опубликовано и никакой repository здесь не создан.
2. Получить явное разрешение создать Telegram-бота и безопасно подключить его token через secret store. Не отправлять token в переписку и не коммитить `.env`/БД.
3. Реализовать и проверить OAuth 2.1 + PKCE для MCP с issuer/audience/expiry/scopes и привязкой resource. Выполнить двухстороннюю, ограниченную по времени привязку подтверждённого principal к numeric `from.id` и private `chat.id`; подтвердить её в исходном чате dot. Username, forward_origin, локальная переменная и possession bot token не доказывают owner identity.
4. Выбрать только один Telegram ingress: getUpdates **или** webhook. Для getUpdates сохранять update до продвижения offset; Telegram хранит pending updates не дольше 24 часов. Для webhook отдельно проверять `X-Telegram-Bot-Api-Secret-Token`; это не подпись MCP Events.
5. Реализовать MCP 2.0, протокол `2026-07-28`, authenticated tools и Events lifecycle по официальной документации. Перед callbacks нужны HTTPS, запрет redirects и private/local/special IP, проверка DNS в момент подключения с фиксацией проверенного адреса и TLS hostname; до этого сетевой транспорт должен оставаться запрещённым.
6. Проверить callback challenge и Standard Webhooks подпись точных body bytes; безопасно хранить/ротировать subscription secret, корректно обрабатывать expiry/revocation/retry/idempotency и ограничения размера. `2xx` callback означает только приём, не завершённый ответ dot.
7. После явного разрешения подключить custom MCP plugin в существующий dot и создать подписку с узкой инструкцией. Первый тест — только эхо несекретного nonce; Telegram-текст не должен разрешать доступ к файлам, почте, платежам или расширение прав. Проверить всю цепочку до подтверждённого Telegram reply, остановку подписки и отсутствие feedback loops.
8. Голос рассматривать только после подтверждения текстового E2E. Отдельное WebRTC/Realtime API приложение само по себе создаёт другой агентный путь, а не голосовой канал этого dot; голос и звонки здесь не реализованы.

## Источники и границы исследования

Проверено 29.10.2026. Условия доступа/account/workspace нужно проверить на целевом аккаунте, они не установлены этим mock.

- [OpenAI MCP Events](https://developers.openai.com/plugins/build/mcp-events): поддержка dots, MCP2, event/subscription/callback contract, подпись и доставка.
- [MCP server](https://developers.openai.com/plugins/build/mcp-server) и [OAuth](https://developers.openai.com/plugins/build/auth): сервер, tools и аутентификация.
- [Подключение custom plugin](https://developers.openai.com/plugins/deploy/connect-chatgpt) и [Security & privacy](https://developers.openai.com/plugins/guides/security-privacy).
- [Telegram getUpdates](https://core.telegram.org/bots/api#getupdates), [setWebhook](https://core.telegram.org/bots/api#setwebhook), [sendMessage](https://core.telegram.org/bots/api#sendmessage), [deep linking](https://core.telegram.org/bots/features#deep-linking).

Реализация на Python выбрана для проверяемости: стенд использует только стандартную библиотеку и проверен на Python 3.12.14. Go scaffold без запуска тестов был бы менее полезен. Внешние Python-зависимости и дополнительный toolchain не устанавливались.

## Файлы

`stand/core.py` — inbox, фильтры, mock authorization, dry reply, запрет сети. `stand/__main__.py` — demo/JSONL/loopback harness. `stand/mcp_contract.py` — offline fixtures. `tests/test_stand.py` — проверки. `env.example` — только синтетические значения. `VERIFICATION.md` — точные результаты запусков.
