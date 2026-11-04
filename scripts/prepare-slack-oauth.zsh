#!/bin/zsh

# Rotate the one-time Slack OAuth setup token, deploy callback-only mode, and
# open the validated authorization URL in a private browser window. No relay or
# OAuth approval is performed by this script.

emulate -L zsh
setopt ERR_EXIT NO_UNSET PIPE_FAIL
unsetopt XTRACE

readonly REPO="Almaz03/jarvis"
readonly WORKFLOW="CI and deploy"
readonly START_URL="https://jarvis.akalmaz.tech/slack/oauth/start"

SLACK_SETUP_TOKEN=""
OAUTH_RESPONSE=""
AUTH_URL=""
BROWSER_APP=""
BROWSER_FLAG=""

cleanup() {
  unset SLACK_SETUP_TOKEN OAUTH_RESPONSE AUTH_URL
}
trap cleanup EXIT INT TERM HUP

die() {
  print -u2 -- "Ошибка: $1"
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || die "не найдена команда $1"
}

detect_private_browser() {
  if [[ -d "/Applications/Google Chrome.app" ]]; then
    BROWSER_APP="Google Chrome"
    BROWSER_FLAG="--incognito"
  elif [[ -d "/Applications/Brave Browser.app" ]]; then
    BROWSER_APP="Brave Browser"
    BROWSER_FLAG="--incognito"
  elif [[ -d "/Applications/Microsoft Edge.app" ]]; then
    BROWSER_APP="Microsoft Edge"
    BROWSER_FLAG="--inprivate"
  else
    die "нужен Google Chrome, Brave или Microsoft Edge для приватного окна"
  fi
}

validate_oauth_response() {
  python3 -c '
import json, sys
from urllib.parse import parse_qs, urlsplit

value = json.load(sys.stdin)
url = value["authorization_url"]
parsed = urlsplit(url)
query = parse_qs(parsed.query)

assert (parsed.scheme, parsed.netloc, parsed.path) == (
    "https", "slack.com", "/oauth/v2_user/authorize"
)
assert query.get("team") == ["T039VA2H3V5"]
assert set(query.get("scope", [""])[0].split(",")) == {
    "chat:write", "im:history"
}
assert query.get("redirect_uri") == [
    "https://jarvis.akalmaz.tech/slack/oauth/callback"
]
assert query.get("client_id", [""])[0]
assert query.get("state", [""])[0]

print(url, end="")
'
}

self_test() {
  local synthetic actual
  synthetic='{"authorization_url":"https://slack.com/oauth/v2_user/authorize?client_id=123.456&scope=chat%3Awrite%2Cim%3Ahistory&redirect_uri=https%3A%2F%2Fjarvis.akalmaz.tech%2Fslack%2Foauth%2Fcallback&state=synthetic-state&team=T039VA2H3V5"}'
  actual="$(print -rn -- "$synthetic" | validate_oauth_response)"
  [[ "$actual" == https://slack.com/oauth/v2_user/authorize\?* ]] || die "self-test OAuth validation"
  print "self-test: ok"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
  exit 0
fi
[[ $# -eq 0 ]] || die "поддерживается только опция --self-test"

for tool in gh curl python3 open; do
  need "$tool"
done
detect_private_browser
gh auth status >/dev/null 2>&1 || die "сначала выполни gh auth login"

typeset PREVIOUS_RUN_ID RUN_ID
PREVIOUS_RUN_ID="$(
  gh run list \
    --repo "$REPO" \
    --workflow "$WORKFLOW" \
    --event workflow_dispatch \
    --limit 1 \
    --json databaseId \
    --jq '.[0].databaseId // ""' 2>/dev/null
)"

SLACK_SETUP_TOKEN="$(
  python3 -c 'import secrets; print(secrets.token_urlsafe(48), end="")'
)"
[[ ${#SLACK_SETUP_TOKEN} -ge 32 ]] || die "не удалось создать setup token"

print -rn -- "$SLACK_SETUP_TOKEN" |
  gh secret set SLACK_OAUTH_SETUP_TOKEN --repo "$REPO" --env production ||
  die "не удалось заменить GitHub Environment secret"

gh workflow run "$WORKFLOW" --repo "$REPO" --ref main ||
  die "не удалось запустить deployment"

RUN_ID=""
for _attempt in {1..30}; do
  RUN_ID="$(
    gh run list \
      --repo "$REPO" \
      --workflow "$WORKFLOW" \
      --event workflow_dispatch \
      --limit 1 \
      --json databaseId \
      --jq '.[0].databaseId // ""'
  )"
  if [[ -n "$RUN_ID" && "$RUN_ID" != "$PREVIOUS_RUN_ID" ]]; then
    break
  fi
  sleep 1
done
[[ -n "$RUN_ID" && "$RUN_ID" != "$PREVIOUS_RUN_ID" ]] ||
  die "новый GitHub Actions run не найден"

gh run watch "$RUN_ID" --repo "$REPO" --exit-status ||
  die "deployment завершился ошибкой; OAuth не запускался"

OAUTH_RESPONSE="$(
  {
    print 'silent'
    print 'show-error'
    print 'fail-with-body'
    print 'request = "POST"'
    print -r -- "url = \"${START_URL}\""
    print 'header = "Accept: application/json"'
    print -r -- "header = \"Authorization: Bearer ${SLACK_SETUP_TOKEN}\""
  } | curl --config -
)" || die "защищённый OAuth start endpoint не ответил"

AUTH_URL="$(print -rn -- "$OAUTH_RESPONSE" | validate_oauth_response)" ||
  die "ответ OAuth endpoint не прошёл проверку"

open -na "$BROWSER_APP" --args "$BROWSER_FLAG" "$AUTH_URL" ||
  die "не удалось открыть приватное окно браузера"

print "Экран Slack открыт в приватном окне. Проверь workspace и два scope."
print "Не нажимай Allow до отдельного подтверждения."
