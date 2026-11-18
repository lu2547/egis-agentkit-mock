"""为单个 MCP 签发个人 OAuth 令牌，并处理登录、确认、刷新及撤销。

核心能力
- 复用 MCP SDK 校验客户端、回调地址、Scope 和 PKCE。
- 每个实例独立保存客户端、授权码及令牌，重启后重新授权。
- 授权确认复用开发登录账号，令牌只适用于对应 MCP。
"""

import secrets
import time
from dataclasses import dataclass
from html import escape
from typing import Annotated

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from mcp.server.auth.handlers.token import TokenHandler
from mcp.server.auth.middleware.client_auth import ClientAuthenticator
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.server.auth.routes import build_metadata, create_auth_routes
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyHttpUrl, TypeAdapter, UrlConstraints
from starlette.routing import Route

from egis_agentkit_mock.app import MOCK_PASSWORD, MOCK_USERS

from .settings import InstanceSettings, MockSettings


@dataclass
class PendingConsent:
    client: OAuthClientInformationFull
    params: AuthorizationParams
    expires_at: float


@dataclass
class TokenPair:
    access: AccessToken
    refresh: RefreshToken


class MockOAuthProvider(
    OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]
):
    """实现 SDK 授权协议，保存一个独立实例的临时认证状态。"""

    def __init__(self, settings: MockSettings, instance: InstanceSettings):
        self.settings = settings.oauth
        self.instance = instance
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.pending: dict[str, PendingConsent] = {}
        self.codes: dict[str, AuthorizationCode] = {}
        self.access: dict[str, TokenPair] = {}
        self.refresh: dict[str, TokenPair] = {}

    async def get_client(self, client_id):
        return self.clients.get(client_id)

    async def register_client(self, client_info):
        """公开客户端仅能登记配置中的开发回调地址。"""
        if client_info.token_endpoint_auth_method != "none":
            raise RegistrationError(
                "invalid_client_metadata", "Use a public PKCE client"
            )
        if any(
            str(uri) not in self.settings.redirect_uris
            for uri in client_info.redirect_uris or []
        ):
            raise RegistrationError(
                "invalid_redirect_uri", "Redirect URI is not configured for this mock"
            )
        self.clients[client_info.client_id] = client_info

    async def authorize(self, client, params):
        """确认目标资源后跳转至本实例的登录确认页面。"""
        if params.resource != self.instance.resource:
            raise AuthorizeError("invalid_target", "Unknown MCP resource")
        self._prune()
        identifier = secrets.token_urlsafe()
        self.pending[identifier] = PendingConsent(
            client, params, time.time() + self.settings.consent_lifetime_seconds
        )
        return self.instance.issuer + "/consent?request_id=" + identifier

    def _prune(self):
        """清除已过期的临时授权状态。"""
        now = time.time()
        self.pending = {
            key: value for key, value in self.pending.items() if value.expires_at > now
        }
        self.codes = {
            key: value for key, value in self.codes.items() if value.expires_at > now
        }
        for pair in list(self.refresh.values()):
            if pair.refresh.expires_at <= now:
                self._remove_pair(pair)

    def consent(self, identifier, user_id, password, decision):
        """校验登录信息，一次性消费授权确认并生成授权码。"""
        pending = self.pending.get(identifier)
        if pending is None or pending.expires_at <= time.time():
            raise HTTPException(400, "授权请求已失效，请重新发起")
        if user_id not in MOCK_USERS or not secrets.compare_digest(
            password.encode(), MOCK_PASSWORD.encode()
        ):
            raise HTTPException(401, "用户名或密码错误")
        if decision not in {"approve", "deny"}:
            raise HTTPException(400, "无效的授权操作")
        del self.pending[identifier]
        params = pending.params
        if decision == "deny":
            return construct_redirect_uri(
                str(params.redirect_uri), error="access_denied", state=params.state
            )
        code = AuthorizationCode(
            code=secrets.token_urlsafe(),
            client_id=pending.client.client_id,
            scopes=params.scopes or self.settings.scopes,
            expires_at=time.time() + self.settings.code_lifetime_seconds,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=self.instance.resource,
            subject=user_id,
        )
        self.codes[code.code] = code
        return construct_redirect_uri(
            str(params.redirect_uri), code=code.code, state=params.state
        )

    async def load_authorization_code(self, client, authorization_code):
        return self.codes.get(authorization_code)

    async def exchange_authorization_code(self, client, authorization_code):
        if self.codes.pop(authorization_code.code, None) is None:
            raise TokenError("invalid_grant", "Authorization code was already consumed")
        return self._issue(
            client.client_id, authorization_code.subject, authorization_code.scopes
        )

    def _issue(self, client_id, subject, scopes):
        """创建属于当前 MCP 的访问令牌与刷新令牌。"""
        self._prune()
        now = int(time.time())
        access = AccessToken(
            token=secrets.token_urlsafe(),
            client_id=client_id,
            subject=subject,
            scopes=scopes,
            expires_at=now + self.settings.access_lifetime_seconds,
            resource=self.instance.resource,
            claims={"iss": self.instance.issuer},
        )
        refresh = RefreshToken(
            token=secrets.token_urlsafe(),
            client_id=client_id,
            subject=subject,
            scopes=scopes,
            expires_at=now + self.settings.refresh_lifetime_seconds,
            resource=self.instance.resource,
        )
        pair = TokenPair(access, refresh)
        self.access[access.token] = pair
        self.refresh[refresh.token] = pair
        return OAuthToken(
            access_token=access.token,
            token_type="Bearer",
            expires_in=self.settings.access_lifetime_seconds,
            refresh_token=refresh.token,
            scope=" ".join(scopes),
        )

    async def load_refresh_token(self, client, refresh_token):
        pair = self.refresh.get(refresh_token)
        return (
            pair.refresh
            if pair and pair.refresh.client_id == client.client_id
            else None
        )

    async def exchange_refresh_token(self, client, refresh_token, scopes):
        pair = self.refresh.get(refresh_token.token)
        if pair is None:
            raise TokenError("invalid_grant", "Refresh token was already consumed")
        self._remove_pair(pair)
        return self._issue(client.client_id, refresh_token.subject, scopes)

    async def load_access_token(self, token):
        pair = self.access.get(token)
        return pair.access if pair and pair.access.expires_at > time.time() else None

    def _remove_pair(self, pair):
        self.access.pop(pair.access.token, None)
        self.refresh.pop(pair.refresh.token, None)

    async def revoke_token(self, token):
        pair = self.access.get(token.token) or self.refresh.get(token.token)
        if pair:
            self._remove_pair(pair)


def _consent_page(provider, request_id, error=""):
    pending = provider.pending.get(request_id)
    if pending is None or pending.expires_at <= time.time():
        raise HTTPException(400, "授权请求已失效，请重新发起")
    return HTMLResponse(
        f"""<!doctype html><html lang="zh-CN"><meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{escape(provider.instance.display_name)}授权</title>
        <body style="font:16px system-ui;max-width:460px;margin:72px auto;padding:24px">
        <h1>{escape(provider.instance.display_name)}</h1>
        <p>{escape(pending.client.client_name or "MCP 客户端")}请求使用此服务。</p>
        <p>权限为 {escape(" ".join(pending.params.scopes or provider.settings.scopes))}</p>
        <p>开发账号 luyang、mask、trump、sam，密码均为 123。</p>
        <p role="alert">{escape(error)}</p>
        <form method="post" action="/consent">
        <input type="hidden" name="request_id" value="{escape(request_id, quote=True)}">
        <p><label>账号 <input name="user_id" required autocomplete="username"></label></p>
        <p><label>密码 <input name="password" type="password" required autocomplete="current-password"></label></p>
        <button name="decision" value="approve">登录并授权</button>
        <button name="decision" value="deny">拒绝</button>
        </form></body></html>""",
        headers={
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer",
            "X-Frame-Options": "DENY",
        },
    )


def create_oauth_app(settings: MockSettings, instance: InstanceSettings) -> FastAPI:
    """装配一个独立 OAuth 服务，标准协议路由复用 SDK。"""
    provider = MockOAuthProvider(settings, instance)
    app = FastAPI(title=instance.display_name + " OAuth")
    issuer = TypeAdapter(
        Annotated[AnyHttpUrl, UrlConstraints(preserve_empty_path=True)]
    ).validate_python(instance.issuer)
    registration = ClientRegistrationOptions(
        enabled=True,
        valid_scopes=settings.oauth.scopes,
        default_scopes=settings.oauth.scopes,
    )
    routes = create_auth_routes(
        provider,
        issuer_url=issuer,
        client_registration_options=registration,
    )
    token_handler = TokenHandler(provider, ClientAuthenticator(provider))

    async def token(request):
        # 资源绑定在授权与交换两个阶段都核对。
        form = await request.form()
        if form.get("resource") != instance.resource:
            return JSONResponse(
                {"error": "invalid_target"},
                status_code=400,
                headers={"Cache-Control": "no-store"},
            )
        return await token_handler.handle(request)

    app.router.routes.extend(
        route
        for route in routes
        if route.path not in {"/token", "/.well-known/oauth-authorization-server"}
    )
    app.router.routes.append(Route("/token", token, methods=["POST"]))

    # 原生 SDK 支持公开客户端，显式声明供 AgentKit 动态注册和撤销使用。
    document = build_metadata(
        issuer, None, registration, RevocationOptions(enabled=True)
    )
    document.token_endpoint_auth_methods_supported = ["none"]
    document.introspection_endpoint = AnyHttpUrl(instance.issuer + "/introspect")

    async def discovery(request):
        return JSONResponse(document.model_dump(mode="json", exclude_none=True))

    app.router.routes.append(
        Route("/.well-known/oauth-authorization-server", discovery)
    )

    @app.get("/health")
    def health():
        return {"status": "ok", "service": "oauth", "instance": instance.name}

    @app.get("/consent")
    def consent_page(request_id: str):
        return _consent_page(provider, request_id)

    @app.post("/consent")
    async def consent(request: Request):
        form = await request.form()
        identifier = str(form.get("request_id", ""))
        try:
            redirect = provider.consent(
                identifier,
                str(form.get("user_id", "")),
                str(form.get("password", "")),
                form.get("decision"),
            )
        except HTTPException as exc:
            if exc.status_code != 401:
                raise
            response = _consent_page(provider, identifier, exc.detail)
            response.status_code = exc.status_code
            return response
        return RedirectResponse(
            redirect, status_code=302, headers={"Cache-Control": "no-store"}
        )

    @app.post("/introspect")
    async def introspect(request: Request):
        form = await request.form()
        access = await provider.load_access_token(str(form.get("token", "")))
        if access is None:
            return JSONResponse(
                {"active": False}, headers={"Cache-Control": "no-store"}
            )
        return JSONResponse(
            {
                "active": True,
                "client_id": access.client_id,
                "sub": access.subject,
                "scope": " ".join(access.scopes),
                "exp": access.expires_at,
                "aud": access.resource,
                "iss": instance.issuer,
            },
            headers={"Cache-Control": "no-store"},
        )

    @app.post("/revoke")
    async def revoke(request: Request):
        form = await request.form()
        client_id = str(form.get("client_id", ""))
        if await provider.get_client(client_id) is None:
            return JSONResponse({"error": "invalid_client"}, status_code=401)
        value = str(form.get("token", ""))
        pair = provider.access.get(value) or provider.refresh.get(value)
        if pair and pair.access.client_id == client_id:
            await provider.revoke_token(pair.access)
        return Response(status_code=200, headers={"Cache-Control": "no-store"})

    return app
