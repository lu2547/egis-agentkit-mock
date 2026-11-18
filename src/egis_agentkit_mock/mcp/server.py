"""创建独立 MCP 资源服务，通过对应 OAuth 服务验证访问令牌。

核心能力
- 复用 MCP SDK 的 Streamable HTTP、受保护资源发现及 Scope 校验。
- 每次请求核对令牌有效性、签发方和目标资源，撤销后立即拒绝调用。
- 提供报表、通讯录两组不同的演示工具及当前授权用户信息。
"""

import ssl

import httpx
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from starlette.requests import Request
from starlette.responses import JSONResponse

from .settings import InstanceSettings, MockSettings

REPORTS = (
    {
        "id": "sales",
        "name": "销售月报",
        "period": "2026-10",
        "amount": 1280000,
        "currency": "CNY",
    },
    {
        "id": "costs",
        "name": "成本月报",
        "period": "2026-10",
        "amount": 680000,
        "currency": "CNY",
    },
)
PEOPLE = (
    {"name": "luyang", "department": "研发", "email": "luyang@example.test"},
    {"name": "mask", "department": "产品", "email": "mask@example.test"},
    {"name": "trump", "department": "销售", "email": "trump@example.test"},
    {"name": "sam", "department": "运维", "email": "sam@example.test"},
)


class IntrospectionVerifier:
    """只信任该实例的 OAuth 服务，跨服务令牌返回未授权。"""

    def __init__(
        self, settings: MockSettings, instance: InstanceSettings, *, transport=None
    ):
        self.settings, self.instance, self.transport = settings, instance, transport

    async def verify_token(self, token: str) -> AccessToken | None:
        tls = ssl.create_default_context()
        if self.settings.tls.ca_certificate.is_file():
            tls.load_verify_locations(self.settings.tls.ca_certificate)
        async with httpx.AsyncClient(
            verify=tls,
            transport=self.transport,
            timeout=self.settings.http_timeout_seconds,
        ) as http:
            response = await http.post(
                self.instance.issuer + "/introspect", data={"token": token}
            )
            response.raise_for_status()
            data = response.json()
        if (
            not data.get("active")
            or data.get("iss") != self.instance.issuer
            or data.get("aud") != self.instance.resource
        ):
            return None
        return AccessToken(
            token=token,
            client_id=data["client_id"],
            subject=data["sub"],
            scopes=data["scope"].split(),
            expires_at=data["exp"],
            resource=data["aud"],
            claims={"iss": data["iss"]},
        )


def create_mcp_app(
    settings: MockSettings, instance: InstanceSettings, *, transport=None
):
    """为指定实例装配标准 MCP 入口和演示工具。"""
    server = MCPServer(
        instance.name,
        instructions=instance.description,
        token_verifier=IntrospectionVerifier(settings, instance, transport=transport),
        auth=AuthSettings(
            issuer_url=instance.issuer,
            resource_server_url=instance.resource,
            required_scopes=settings.oauth.scopes,
            validate_token_resource=True,
        ),
    )

    @server.tool()
    def whoami() -> dict:
        """返回本次 OAuth 授权的用户及 MCP 服务名称。"""
        token = get_access_token()
        return {"user_id": token.subject, "server": instance.name}

    if instance.name == "reports":

        @server.tool()
        def list_reports() -> list[dict]:
            """列出 Mock 报表的名称、月份、金额及币种。"""
            return list(REPORTS)
    else:

        @server.tool()
        def search_people(query: str) -> list[dict]:
            """按姓名或部门搜索 Mock 通讯录，空字符串返回全部。"""
            return [
                dict(person)
                for person in PEOPLE
                if query.casefold()
                in (person["name"] + person["department"]).casefold()
            ]

    @server.custom_route("/health", methods=["GET"])
    async def health(request: Request):
        return JSONResponse(
            {"status": "ok", "service": "mcp", "instance": instance.name}
        )

    return server.streamable_http_app(
        json_response=True, stateless_http=True, host=settings.public_host
    )
