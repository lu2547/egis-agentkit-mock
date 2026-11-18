import jwt
import pytest
from fastapi.testclient import TestClient

from egis_agentkit_mock.app import create_app


@pytest.fixture
def client():
    with TestClient(create_app()) as client:
        yield client


@pytest.mark.parametrize("user_id", ["luyang", "mask", "trump", "sam"])
def test_login_returns_a_verifiable_token_for_the_mock_account(client, user_id):
    response = client.post("/auth/login", json={"user_id": user_id, "password": "123"})
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    payload = response.json()
    assert payload["token_type"] == "bearer"
    token = payload["access_token"]
    jwks = client.get("/.well-known/jwks.json").json()
    key = jwt.PyJWKSet.from_dict(jwks)[jwt.get_unverified_header(token)["kid"]]
    assert jwks["keys"][0]["use"] == "sig"
    assert "d" not in jwks["keys"][0]
    claims = jwt.decode(
        token,
        key.key,
        algorithms=["RS256"],
        audience="egis-agentkit",
        issuer="urn:egis:agentkit:mock",
        options={"require": ["exp", "iat", "iss", "aud", "sub"]},
    )
    assert (claims["sub"], claims["name"]) == (user_id, user_id)
    assert claims["exp"] - claims["iat"] == payload["expires_in"]
    assert set(claims) == {"sub", "name", "iss", "aud", "iat", "exp"}


@pytest.mark.parametrize(
    ("user_id", "password"),
    [("luyang", "456"), ("other", "123"), ("LuYang", "123")],
)
def test_login_rejects_bad_credentials_and_non_mock_accounts(client, user_id, password):
    response = client.post(
        "/auth/login", json={"user_id": user_id, "password": password}
    )
    assert response.status_code == 401
    assert "access_token" not in response.json()
