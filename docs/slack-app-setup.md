# Slack app: owner-only relay preparation

This file prepares a separate Slack app for a future Telegram ↔ Slack relay.
It does not install the app, issue a token, deploy the relay, or change the
working Telegram bridge.

## Fixed scope

- Target Slack DM: `D0C7SAYJB24`.
- User scopes: exactly `chat:write` and `im:history`.
- No bot scopes, workspace-wide install, Socket Mode, incoming webhook, or
  identity-customization scope.
- The service must reject every Slack event whose channel is not the target DM
  before storing its content.

Slack does not make these user scopes exclusive to a single DM. A user token
with `im:history` may technically read other direct messages available to the
authorizing user. The channel allowlist is therefore an application boundary,
not a narrower OAuth grant.

## Create the app without granting access

1. Open <https://api.slack.com/apps> while signed into the intended workspace.
2. Select **Create New App → From an app manifest**.
3. Choose the intended workspace and paste `slack-app-manifest.json` in the
   JSON editor.
4. Review the preview. It must show only the two **User Token Scopes** above
   and no bot scopes. Creating the app does not install it.

The app management UI will then provide a Client ID, Client Secret, and Signing
Secret. Do not paste any of them into chat, Git, shell history, CI logs, or the
manifest.

## OAuth grant boundary

The user-only authorization URL will be generated server-side after the app
exists. Its shape is:

```text
https://slack.com/oauth/v2_user/authorize?client_id=CLIENT_ID&scope=chat%3Awrite%2Cim%3Ahistory&redirect_uri=https%3A%2F%2Fjarvis.akalmaz.tech%2Fslack%2Foauth%2Fcallback&state=ONE_TIME_RANDOM_VALUE
```

The callback must verify the one-time `state`, exchange the short-lived code
using `oauth.v2.user.access`, and validate the returned workspace ID, owner user
ID, token type, and exact granted scopes. The token and refresh material must be
stored server-side with owner-only filesystem permissions and never returned to
the browser or logs.

Do not approve the OAuth screen until the callback exists and the user has
separately confirmed the exact workspace, user, scopes, storage location, and
one-message test. Slack scopes are additive; reauthorization cannot silently
downgrade an already broader token.

## Events API comes later

The manifest intentionally does not enable Event Subscriptions. Slack requires
manual verification of the HTTPS Request URL. Enabling it before the signed
endpoint exists would create an unverified configuration.

After separate approval and deployment of that endpoint, update the app with:

```json
{
  "settings": {
    "event_subscriptions": {
      "request_url": "https://jarvis.akalmaz.tech/slack/events",
      "user_events": ["message.im"]
    }
  }
}
```

The endpoint must verify Slack request signatures and timestamps, acknowledge
within three seconds, durably deduplicate event IDs, and process only the exact
owner and target DM. It must not relay its own API-authored messages back to
Telegram.

## First live test

Before enabling the relay, send one harmless API-authored owner message to the
target DM: `relay-test: ответь OK`. Success requires the existing dot to answer
that specific message. Direct manual Slack success does not prove that an
API-authored user-token message is accepted as an owner command.
