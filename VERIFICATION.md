# Проверка стенда

Дата: 2026-10-29
Окружение: managed cloud environment, Python 3.12.14, Docker 28.4.0

## Результаты

- `python3 -m unittest discover -s tests -v`: **34/34 PASS**.
- `python3 -m compileall -q stand tests`: **PASS**.
- `python3 -m stand demo`: **PASS**; финальный статус:
  `{"result":"offline_only","network_calls":0,"dot_connected":false}`.
- `docker build -t jarvis:test .`: **PASS**.
- Контейнерный demo с `--network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m`: **PASS** с тем же финальным статусом `offline_only`.
- `docker compose --profile mcp config` с синтетическим env: **PASS**.
- `caddy validate` для `Caddyfile`: **PASS**.
- Unit-тесты внутри read-only Docker image без сети: **34/34 PASS**.

## Найденное и исправленное

Первоначальный Dockerfile копировал приватные исходные файлы с правами `0600`, после чего непривилегированный `USER 65534` получал `PermissionError`. В образ добавлена нормализация прав только для скопированных каталогов приложения: `chmod -R a=rX`. Права исходников и локальной SQLite-БД на хосте не ослаблялись.

## Что не проверено

- Реальный Telegram Bot API; long polling проверен только через fake transport.
- Реальный Auth0 login/token через ChatGPT и live JWKS verification.
- Реальный callback challenge и доставка MCP Event в ChatGPT.
- Доставка события существующему dot и обратный ответ в Telegram.
- Голосовые сообщения и звонки.

Тесты live-границ используют локальные ключи/fake transports и не доказывают
рабочий end-to-end канал.
