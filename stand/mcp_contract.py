"""Offline contract fixtures, NOT a complete MCP 2.0 server or auth implementation.
Reviewed source: https://developers.openai.com/plugins/build/mcp-events (2026-10-29).
"""
PROTOCOL_VERSION = "2026-07-28"


def discover_result():
    return {"resultType": "complete", "supportedVersions": [PROTOCOL_VERSION],
            "capabilities": {"tools": {}, "events": {}}}


def events_list_result():
    return {"events": [{
        "name": "telegram.message.created",
        "description": "An untrusted text message in the bound owner's private Telegram inbox.",
        "delivery": ["webhook"],
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "payloadSchema": {"type": "object", "properties": {
            "message_ref": {"type": "string"}, "source": {"type": "string", "const": "telegram"},
            "untrusted": {"type": "boolean", "const": True}},
            "required": ["message_ref", "source", "untrusted"], "additionalProperties": False},
    }]}


def disabled_subscription_error(request_id):
    return {"jsonrpc": "2.0", "id": request_id, "error": {
        "code": -32015, "message": "Offline stand: callback transport disabled",
        "data": {"reason": "transport_disabled"}}}
