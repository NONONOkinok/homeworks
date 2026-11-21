"""
Access Token: выпуск JWT и проверка подписи и полей.
Сессии в базе здесь не создаются.
"""

import base64
import json

import jwt
import pytest

from token_manager import (
    ACCESS_TTL_SECONDS,
    ALGORITHM,
    AUDIENCE,
    ISSUER,
    AccessTokenError,
    issue_access_token,
    verify_access_token,
)

KEY = b"k" * 32
OTHER_KEY = b"o" * 32
NOW = 1_700_000_000
USER = "user-1"
SESSION = "session-1"


def _issue(**kwargs) -> str:
    params = {"user_id": USER, "session_id": SESSION, "signing_key": KEY, "now": NOW}
    params.update(kwargs)
    return issue_access_token(**params)


def _claims(**overrides) -> dict:
    payload = {
        "sub": USER,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": NOW,
        "nbf": NOW,
        "exp": NOW + ACCESS_TTL_SECONDS,
        "jti": "token-1",
        "sid": SESSION,
        "token_use": "access",
    }
    payload.update(overrides)
    return payload


def _sign(payload: dict, key: bytes = KEY, algorithm: str = ALGORITHM) -> str:
    return jwt.encode(payload, key, algorithm=algorithm, headers={"typ": "JWT"})


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _rejected(token: str, code: str, now: int = NOW) -> None:
    with pytest.raises(AccessTokenError) as caught:
        verify_access_token(token, KEY, now=now)
    assert caught.value.code == code
    assert str(caught.value) == "Пропуск отклонён"
    if token:
        assert token not in str(caught.value)


class TestIssueAccessToken:
    """Выпуск пропуска: ровно нужные поля и срок 15 минут."""

    def test_contains_required_claims(self):
        token = _issue()
        claims = verify_access_token(token, KEY, now=NOW)
        assert claims["sub"] == USER
        assert claims["sid"] == SESSION
        assert claims["iss"] == ISSUER
        assert claims["aud"] == AUDIENCE
        assert claims["token_use"] == "access"
        assert claims["iat"] == NOW
        assert claims["nbf"] == NOW
        assert claims["exp"] == NOW + ACCESS_TTL_SECONDS
        assert claims["exp"] - claims["iat"] == 15 * 60

    def test_each_token_has_its_own_jti(self):
        first = verify_access_token(_issue(), KEY, now=NOW)
        second = verify_access_token(_issue(), KEY, now=NOW)
        assert first["jti"] != second["jti"]

    def test_header_is_pinned_hs256(self):
        token = _issue()
        header_raw = token.split(".")[0]
        padding = "=" * (-len(header_raw) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_raw + padding))
        assert header["alg"] == "HS256"
        assert header["typ"] == "JWT"

    def test_payload_has_no_secrets(self):
        token = _issue()
        payload_raw = token.split(".")[1]
        padding = "=" * (-len(payload_raw) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_raw + padding))
        assert set(payload) == {
            "sub", "iss", "aud", "iat", "nbf", "exp", "jti", "sid", "token_use",
        }

    def test_rejects_bad_key_and_ids(self):
        with pytest.raises(ValueError):
            issue_access_token(USER, SESSION, b"short", now=NOW)
        with pytest.raises(ValueError):
            issue_access_token("  ", SESSION, KEY, now=NOW)
        with pytest.raises(ValueError):
            issue_access_token(USER, "", KEY, now=NOW)


class TestVerifyAccessToken:
    """Подпись проверяется раньше, чем полям начинают доверять."""

    def test_accepts_token_until_last_second(self):
        token = _issue()
        claims = verify_access_token(token, KEY, now=NOW + ACCESS_TTL_SECONDS - 1)
        assert claims["sub"] == USER

    def test_rejects_expired_token(self):
        _rejected(_issue(), "expired", now=NOW + ACCESS_TTL_SECONDS)

    def test_rejects_bad_signature(self):
        token = _issue()
        broken = token[:-2] + ("a" if token[-2] != "a" else "b") + token[-1]
        _rejected(broken, "bad_signature")

    def test_rejects_other_key(self):
        token = _issue()
        with pytest.raises(AccessTokenError) as caught:
            verify_access_token(token, OTHER_KEY, now=NOW)
        assert caught.value.code == "bad_signature"

    def test_rejects_algorithm_none(self):
        header = _b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        body = _b64(json.dumps(_claims()).encode())
        _rejected(f"{header}.{body}.", "bad_algorithm")

    def test_rejects_swapped_algorithm(self):
        signed = _sign(_claims(), key=b"k" * 48, algorithm="HS384")
        _rejected(signed, "bad_algorithm")

    def test_rejects_wrong_issuer(self):
        _rejected(_sign(_claims(iss="other-app")), "bad_issuer")

    def test_rejects_wrong_audience(self):
        _rejected(_sign(_claims(aud="other-app")), "bad_audience")

    def test_rejects_audience_list(self):
        _rejected(_sign(_claims(aud=[AUDIENCE, "extra"])), "bad_audience")

    def test_rejects_wrong_purpose(self):
        _rejected(_sign(_claims(token_use="refresh")), "bad_purpose")

    @pytest.mark.parametrize("field", ["sub", "iss", "aud", "iat", "exp", "jti", "sid", "token_use"])
    def test_rejects_missing_claim(self, field):
        payload = _claims()
        del payload[field]
        _rejected(_sign(payload), "missing_claim")

    def test_rejects_empty_sid(self):
        _rejected(_sign(_claims(sid="")), "missing_claim")

    def test_rejects_future_iat(self):
        later = NOW + 60
        _rejected(_sign(_claims(iat=later, nbf=later, exp=later + ACCESS_TTL_SECONDS)), "not_yet_valid")

    def test_rejects_lifetime_other_than_15_minutes(self):
        _rejected(_sign(_claims(exp=NOW + ACCESS_TTL_SECONDS + 1)), "bad_lifetime")

    def test_rejects_malformed_token(self):
        _rejected("not-a-jwt", "bad_token")
        _rejected("", "bad_token")
