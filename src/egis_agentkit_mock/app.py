"""模拟公司登录和 JWKS，独立签发开发环境 JWT。"""

import json
import time
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field

ISSUER = "urn:egis:agentkit:mock"
AUDIENCE = "egis-agentkit"
JWT_ALGORITHM = "RS256"
JWT_LIFETIME_SECONDS = 3600
MOCK_USERS = frozenset({"luyang", "mask", "trump", "sam"})
MOCK_PASSWORD = "123"


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = JWT_LIFETIME_SECONDS


def create_app() -> FastAPI:
    app = FastAPI(title="Egis AgentKit Mock")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = json.loads(
        jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key())
    )
    public_key.update(kid=uuid4().hex, use="sig", alg=JWT_ALGORITHM)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/.well-known/jwks.json")
    def jwks():
        return {"keys": [public_key]}

    @app.post("/auth/login")
    def login(body: LoginRequest, response: Response) -> LoginResponse:
        response.headers["Cache-Control"] = "no-store"
        if body.user_id not in MOCK_USERS or body.password != MOCK_PASSWORD:
            raise HTTPException(
                401, "用户名或密码错误", headers={"Cache-Control": "no-store"}
            )
        now = int(time.time())
        token = jwt.encode(
            {
                "sub": body.user_id,
                "name": body.user_id,
                "iss": ISSUER,
                "aud": AUDIENCE,
                "iat": now,
                "exp": now + JWT_LIFETIME_SECONDS,
            },
            private_key,
            algorithm=JWT_ALGORITHM,
            headers={"kid": public_key["kid"]},
        )
        return LoginResponse(access_token=token)

    return app
