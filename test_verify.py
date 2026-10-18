from datetime import datetime, timedelta, timezone

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

import main


def create_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


private_key, public_key = create_keypair()
main.PUBLIC_KEY = public_key
client = TestClient(main.app)


def mint_token(**overrides):
    claims = {
        "iss": main.ISSUER,
        "aud": main.AUDIENCE,
        "sub": "user-123",
        "email": "student@example.com",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
    }
    claims.update(overrides)
    return jwt.encode(claims, private_key, algorithm="RS256")


def test_valid_token():
    response = client.post("/verify", json={"token": mint_token()})
    assert response.status_code == 200
    assert response.json() == {
        "valid": True,
        "email": "student@example.com",
        "sub": "user-123",
        "aud": main.AUDIENCE,
    }


def test_expired_wrong_audience_and_tampered_tokens():
    expired = mint_token(exp=datetime.now(timezone.utc) - timedelta(minutes=1))
    wrong_audience = mint_token(aud="wrong-audience")
    valid = mint_token()
    header, payload, signature = valid.split(".")
    tampered = f"{header}.{payload[:-1]}{'A' if payload[-1] != 'A' else 'B'}.{signature}"

    for token in (expired, wrong_audience, tampered):
        response = client.post("/verify", json={"token": token})
        assert response.status_code == 401
        assert response.json() == {"valid": False}


def test_other_invalid_requests():
    cases = [
        {"json": {"token": "not-a-jwt"}},
        {"json": {}},
        {"content": b"not-json", "headers": {"content-type": "application/json"}},
        {"json": {"token": mint_token(iss="wrong-issuer")}},
    ]

    for case in cases:
        response = client.post("/verify", **case)
        assert response.status_code == 401
        assert response.json() == {"valid": False}
