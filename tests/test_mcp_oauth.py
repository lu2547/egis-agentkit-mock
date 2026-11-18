"""用真实 HTTP 端点验证两套授权、令牌隔离与 MCP 工具调用。"""

import base64
import hashlib
import json
import re
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi.testclient import TestClient

CALLBACK = "https://localhost:5179/connectors/oauth/callback"
VERIFIER = "mock-pkce-verifier-with-enough-entropy-for-development"


@pytest.fixture
def services():
    from egis_agentkit_mock.mcp.oauth import create_oauth_app
    from egis_agentkit_mock.mcp.server import create_mcp_app
    from egis_agentkit_mock.mcp.settings import load_settings

    settings = load_settings()
    result = []
    for instance in settings.instances:
        oauth_app = create_oauth_app(settings, instance)
        oauth = TestClient(oauth_app, base_url=instance.issuer)
        mcp = TestClient(
            create_mcp_app(
                settings, instance, transport=httpx.ASGITransport(app=oauth_app)
            ),
            base_url=instance.resource.removesuffix("/mcp"),
        )
        result.append((instance, oauth, mcp))
    with result[0][1], result[0][2], result[1][1], result[1][2]:
        yield result


def begin_authorization(oauth, resource):
    registered = oauth.post(
        "/register",
        json={
            "client_name": "AgentKit integration test",
            "redirect_uris": [CALLBACK],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        },
    )
    assert registered.status_code == 201, registered.text
    client_id = registered.json()["client_id"]
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest())
        .decode()
        .rstrip("=")
    )
    authorization = oauth.get(
        "/authorize",
        params={
            "client_id": client_id,
            "redirect_uri": CALLBACK,
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "mcp:tools",
            "state": "test-state",
            "resource": resource,
        },
        follow_redirects=True,
    )
    assert authorization.status_code == 200, authorization.text
    request_id = re.search(r'name="request_id" value="([^"]+)"', authorization.text)[1]
    return client_id, request_id


def authorize(oauth, resource, user="luyang"):
    client_id, request_id = begin_authorization(oauth, resource)
    approved = oauth.post(
        "/consent",
        data={
            "request_id": request_id,
            "user_id": user,
            "password": "123",
            "decision": "approve",
        },
        follow_redirects=False,
    )
    assert approved.status_code == 302, approved.text
    callback = urlsplit(approved.headers["location"])
    assert callback._replace(query="").geturl() == CALLBACK
    query = parse_qs(callback.query)
    assert query["state"] == ["test-state"]
    return client_id, query["code"][0]


def exchange(oauth, resource, client_id, code, verifier=VERIFIER):
    return oauth.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "redirect_uri": CALLBACK,
            "code": code,
            "code_verifier": verifier,
            "resource": resource,
        },
    )


def rpc(client, method, token=None, params=None):
    headers = {"Accept": "application/json, text/event-stream"}
    if token:
        headers["Authorization"] = "Bearer " + token
    return client.post(
        "/mcp",
        headers=headers,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
    )


def test_both_servers_advertise_their_own_authorization_service(services):
    for instance, oauth, mcp in services:
        denied = mcp.get("/mcp")
        assert denied.status_code == 401
        assert 'resource_metadata="' in denied.headers["www-authenticate"]
        metadata = mcp.get("/.well-known/oauth-protected-resource/mcp").json()
        assert metadata["resource"] == instance.resource
        assert metadata["authorization_servers"] == [instance.issuer]
        discovery = oauth.get("/.well-known/oauth-authorization-server").json()
        assert discovery["issuer"] == instance.issuer
        assert "S256" in discovery["code_challenge_methods_supported"]


def test_authorized_tools_return_the_correct_user_and_reject_the_other_issuer(services):
    tokens = []
    for (instance, oauth, mcp), user in zip(services, ("luyang", "sam"), strict=True):
        client_id, code = authorize(oauth, instance.resource, user)
        response = exchange(oauth, instance.resource, client_id, code)
        assert response.status_code == 200, response.text
        assert response.headers["cache-control"] == "no-store"
        token = response.json()["access_token"]
        tokens.append(token)
        initialized = rpc(
            mcp,
            "initialize",
            token,
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1.0"},
            },
        )
        assert initialized.status_code == 200, initialized.text
        tools = rpc(mcp, "tools/list", token).json()["result"]["tools"]
        assert len(tools) >= 2
        result = rpc(
            mcp, "tools/call", token, {"name": "whoami", "arguments": {}}
        ).json()["result"]
        assert result["isError"] is False
        identity = json.loads(result["content"][0]["text"])
        assert identity["user_id"] == user
        assert identity["server"] == instance.name
        assert exchange(oauth, instance.resource, client_id, code).status_code == 400
    assert rpc(services[0][2], "tools/list", tokens[1]).status_code == 401
    assert rpc(services[1][2], "tools/list", tokens[0]).status_code == 401


def test_pkce_refresh_rotation_and_revocation(services):
    instance, oauth, mcp = services[0]
    client_id, code = authorize(oauth, instance.resource, "sam")
    assert (
        exchange(
            oauth, instance.resource, client_id, code, "wrong-verifier"
        ).status_code
        == 400
    )
    tokens = exchange(oauth, instance.resource, client_id, code).json()
    refresh_request = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": tokens["refresh_token"],
        "resource": instance.resource,
    }
    refreshed = oauth.post("/token", data=refresh_request)
    assert refreshed.status_code == 200, refreshed.text
    assert refreshed.json()["refresh_token"] != tokens["refresh_token"]
    assert oauth.post("/token", data=refresh_request).status_code == 400
    current = refreshed.json()
    assert rpc(mcp, "tools/list", current["access_token"]).status_code == 200
    revoked = oauth.post(
        "/revoke", data={"client_id": client_id, "token": current["refresh_token"]}
    )
    assert revoked.status_code == 200, revoked.text
    assert rpc(mcp, "tools/list", current["access_token"]).status_code == 401


def test_consent_rejects_bad_login_and_supports_denial(services):
    instance, oauth, _ = services[0]
    _, request_id = begin_authorization(oauth, instance.resource)
    bad = oauth.post(
        "/consent",
        data={
            "request_id": request_id,
            "user_id": "other",
            "password": "123",
            "decision": "approve",
        },
    )
    assert bad.status_code == 401
    denied = oauth.post(
        "/consent",
        data={
            "request_id": request_id,
            "user_id": "sam",
            "password": "123",
            "decision": "deny",
        },
        follow_redirects=False,
    )
    assert parse_qs(urlsplit(denied.headers["location"]).query)["error"] == [
        "access_denied"
    ]


def test_authorization_rejects_another_resource_and_unlisted_redirect(services):
    _, oauth, _ = services[0]
    response = oauth.post(
        "/register",
        json={
            "redirect_uris": ["https://attacker.example/callback"],
            "token_endpoint_auth_method": "none",
        },
    )
    assert response.status_code == 400
    registered = oauth.post(
        "/register",
        json={"redirect_uris": [CALLBACK], "token_endpoint_auth_method": "none"},
    ).json()
    denied = oauth.get(
        "/authorize",
        params={
            "client_id": registered["client_id"],
            "redirect_uri": CALLBACK,
            "response_type": "code",
            "code_challenge": "challenge",
            "resource": services[1][0].resource,
        },
        follow_redirects=False,
    )
    assert denied.status_code == 302
    assert parse_qs(urlsplit(denied.headers["location"]).query)["error"] == [
        "invalid_target"
    ]


def test_exchange_rejects_resource_substitution_and_client_substitution(services):
    instance, oauth, _ = services[0]
    client_id, code = authorize(oauth, instance.resource)
    wrong_resource = exchange(oauth, services[1][0].resource, client_id, code)
    assert wrong_resource.status_code == 400
    assert wrong_resource.json()["error"] == "invalid_target"
    other_client, _ = begin_authorization(oauth, instance.resource)
    wrong_client = exchange(oauth, instance.resource, other_client, code)
    assert wrong_client.status_code == 400
    assert wrong_client.json()["error"] == "invalid_grant"
    assert exchange(oauth, instance.resource, client_id, code).status_code == 200


def test_expired_access_and_refresh_tokens_are_rejected(services, monkeypatch):
    instance, oauth, mcp = services[0]
    client_id, code = authorize(oauth, instance.resource)
    tokens = exchange(oauth, instance.resource, client_id, code).json()
    now = time.time()
    monkeypatch.setattr(
        "egis_agentkit_mock.mcp.oauth.time.time", lambda: now + tokens["expires_in"] + 1
    )
    assert rpc(mcp, "tools/list", tokens["access_token"]).status_code == 401
    monkeypatch.setattr("egis_agentkit_mock.mcp.oauth.time.time", lambda: now + 86400)
    refreshed = oauth.post(
        "/token",
        data={
            "client_id": client_id,
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "resource": instance.resource,
        },
    )
    assert refreshed.status_code == 400
    assert refreshed.json()["error"] == "invalid_grant"
