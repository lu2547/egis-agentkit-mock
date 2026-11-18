# egis-agentkit-mock

独立的 FastAPI 开发认证服务。允许 `luyang`、`mask`、`trump`、`sam` 登录，密码统一为 `123`，账号区分大小写。其他账号或错误密码返回 HTTP 401。请绑定开发机的回环地址。

```sh
uv sync --locked
uv run uvicorn egis_agentkit_mock.app:create_app --factory --host 127.0.0.1 --port 38093
```

- `POST /auth/login` 接收 `user_id` 和 `password`，返回 RS256 Bearer JWT。
- `GET /.well-known/jwks.json` 返回验签公钥。
- `GET /health` 检查 Mock 是否运行，`/docs` 可直接测试登录。

AgentKit 开发环境的 Nacos `agentkit.yaml` 用以下内容替换 `agentkit.user.identity`，递增 `agentkit.revision` 并重启 App。

```yaml
agentkit:
  user:
    identity:
      mode: jwt
      issuer: urn:egis:agentkit:mock
      audience: egis-agentkit
      algorithm: RS256
      jwksUrl: http://127.0.0.1:38093/.well-known/jwks.json
```

开发前端默认把 `/api/auth/login` 转发到该服务。登录后前端携带 JWT 请求 AgentKit 的 `GET /manager/me`，AgentKit 验签后为新用户建档，加入默认公司组并分配普通用户角色。

使用命令行验证整条链路：

```sh
AGENTKIT_MOCK_TOKEN=$(curl -fsS http://127.0.0.1:38093/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"user_id":"luyang","password":"123"}' | jq -er '.access_token')
curl -fsS http://127.0.0.1:38092/manager/me \
  -H "Authorization: Bearer ${AGENTKIT_MOCK_TOKEN}"
```

Mock 每次启动生成新签名密钥，重启后请重新登录。运行 `uv run pytest` 验证登录和验签。

## MCP 与 OAuth Mock

两套 MCP 各自连接一个独立的 OAuth 服务，共四个进程。每套 OAuth 有自己的客户端、授权码、访问令牌和刷新令牌，另一套 MCP 会拒绝这些令牌。授权服务可以与 MCP 分开部署，服务发现由 MCP 的受保护资源元数据声明。[MCP 授权规范](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)

| 服务 | 模拟的业务与示例 | MCP 地址 | OAuth 地址 |
| --- | --- | --- | --- |
| 报表 | 企业报表系统。`list_reports` 返回销售月报、成本月报的月份、金额与币种。可问「列出最近的销售月报和成本月报」。 | `https://localhost:38102/mcp` | `https://localhost:38101` |
| 通讯录 | 企业通讯录。`search_people` 按员工姓名或部门查询邮箱。可问「研发部有哪些人？查一下他们的邮箱」。 | `https://localhost:38104/mcp` | `https://localhost:38103` |

OAuth 登录复用 `luyang`、`mask`、`trump`、`sam`，密码均为 `123`。用户在授权页面选择登录并授权或拒绝，`whoami` 返回此次授权的用户和服务名。

### 启动

在本项目目录执行以下命令。

```sh
uv sync --locked
uv run agentkit-mock-mcp certificates
uv run agentkit-mock-mcp serve
```

`certificates` 在 `.var/tls/` 生成开发 CA 和 HTTPS 证书，已有完整文件时复用。`serve` 同时启动四个进程，Ctrl+C 会关闭全部子进程。任何子服务意外退出时，其余进程也会收尾，启动命令返回失败。

各进程也可以单独启动。

```sh
uv run agentkit-mock-mcp serve --instance reports --service oauth
uv run agentkit-mock-mcp serve --instance reports --service mcp
uv run agentkit-mock-mcp serve --instance directory --service oauth
uv run agentkit-mock-mcp serve --instance directory --service mcp
```

启动参数、四个端口、回调白名单、Scope 和令牌有效期统一在 [settings.toml](src/egis_agentkit_mock/mcp/settings.toml) 中配置。需要不同配置时先复制该文件，使用 `agentkit-mock-mcp --config /path/to/mock.toml serve`。服务默认绑定 `127.0.0.1`。

### 连接 AgentKit

1. 在「管理 → MCP」新增连接器，使用 Streamable HTTP 和 OAuth，服务地址填上表的 MCP 地址。客户端 ID 留空，AgentKit 会动态注册。权限范围可留空，也可填 `mcp:tools`。运行 `uv run agentkit-mock-mcp connectors` 可查看两套登记参数。
2. 在 Nacos 将 `agentkit.connector.oauth.redirectUri` 配置成前端的 HTTPS 回调地址，路径为 `/connectors/oauth/callback`。Mock 默认允许 `https://localhost:5179/connectors/oauth/callback` 和相同端口的 `127.0.0.1` 地址。使用其他地址时同步修改 Mock 的 `oauth.redirect_uris`。
3. 让 App 和沙箱中的 MCP 调用进程信任 `.var/tls/ca.pem`。Python 进程可在启动时设置 `SSL_CERT_FILE` 为该文件的绝对路径。浏览器访问授权页时也需要信任这个开发 CA。前端通过现有 HTTPS 入口提供回调。
4. 管理员登记并开放公司组后，用户到连接器广场点击授权，完成登录确认，再选择添加。报表和通讯录分别授权。

Mock 默认地址用于本机联调。App 或沙箱在其他主机运行时，`public_host` 应配置成它们能访问的 HTTPS 主机名，并由该主机的入口转发四个端口；证书需包含该主机名。容器中的 CA 文件路径也按容器实际挂载位置配置。

OAuth 状态保存在各自进程的内存中，重启 OAuth 后需要重新授权。访问令牌默认有效 300 秒，刷新令牌有效 3600 秒。刷新时轮换两个令牌，撤销任一当前令牌会同时撤销对应的一对令牌。

### 接口与验证

每个服务提供 `GET /health`。OAuth 服务提供以下接口。

| 接口 | 能力 |
| --- | --- |
| `GET /.well-known/oauth-authorization-server` | 发现授权、交换、动态注册和撤销地址 |
| `POST /register` | 注册受回调白名单限制的公开客户端 |
| `GET /authorize` | 校验请求并跳转至登录确认页 |
| `GET /consent`、`POST /consent` | 登录并同意或拒绝授权 |
| `POST /token` | 校验 PKCE、消费一次性授权码或刷新令牌 |
| `POST /introspect` | 供对应 MCP 核对令牌有效性、用户和目标资源 |
| `POST /revoke` | 撤销访问令牌与刷新令牌 |

MCP 使用 SDK 的 Streamable HTTP 入口。未带有效 Token 请求 `/mcp` 会返回 401 和资源元数据位置，元数据指向该实例对应的 OAuth 服务。

```sh
curl --cacert .var/tls/ca.pem https://localhost:38101/health
curl --cacert .var/tls/ca.pem https://localhost:38102/.well-known/oauth-protected-resource/mcp
uv run pytest -q
```

测试覆盖两套发现信息、授权用户、跨服务令牌拒绝、PKCE、授权码重放、刷新轮换、过期、撤销、错误登录、拒绝授权、回调白名单和资源替换。
