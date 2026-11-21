"""
Access Token: короткий пропуск, который подтверждает вход.

Простыми словами. После входа приложение выдаёт записку на 15 минут.
Записка подписана секретом из связки паролей, поэтому её нельзя незаметно
подправить. Прочитать записку может кто угодно: подпись прячет не текст,
а только факт, что текст не меняли. Поэтому внутри нет пароля и нет
Refresh Token.

Технически это JWT в виде JWS с алгоритмом HS256 (RFC 7519 и RFC 7515).
Алгоритм берётся из кода, а не из заголовка токена. Так отсекается подмена
алгоритма, включая alg=none (RFC 8725). Поле jti только называет конкретный
пропуск. По нему сессию не отзывают: отзыв — это состояние сессии в SQLite,
его проверяет следующий этап.
"""

from __future__ import annotations

import time
import uuid

import jwt

ISSUER = "local-auth-app"
AUDIENCE = "local-auth-app"
ALGORITHM = "HS256"
TOKEN_USE_ACCESS = "access"
ACCESS_TTL_SECONDS = 15 * 60

_REQUIRED_CLAIMS = ("sub", "iss", "aud", "iat", "nbf", "exp", "jti", "sid", "token_use")
_MAX_TOKEN_LENGTH = 4096


class AccessTokenError(Exception):
    """Пропуск отклонён. Текст для человека не раскрывает причину и секреты."""

    def __init__(self, code: str):
        self.code = code
        super().__init__("Пропуск отклонён")


def issue_access_token(
    user_id: str,
    session_id: str,
    signing_key: bytes,
    now: int | None = None,
) -> str:
    """Подписывает пропуск на 15 минут. Секрет в токен не вкладывается."""
    _require_id(user_id)
    _require_id(session_id)
    _require_key(signing_key)
    issued_at = _clock(now)
    payload = {
        "sub": user_id,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": issued_at,
        "nbf": issued_at,
        "exp": issued_at + ACCESS_TTL_SECONDS,
        "jti": str(uuid.uuid4()),
        "sid": session_id,
        "token_use": TOKEN_USE_ACCESS,
    }
    token = jwt.encode(payload, signing_key, algorithm=ALGORITHM, headers={"typ": "JWT"})
    if not isinstance(token, str):
        raise AccessTokenError("bad_token")
    return token


def verify_access_token(
    token: str,
    signing_key: bytes,
    now: int | None = None,
) -> dict:
    """
    Проверяет подпись и обязательные поля.

    Возвращает проверенные claims. Не смотрит в SQLite: жива ли сессия,
    решает код сессий перед защищённой операцией. До успешной проверки
    подписи поля токена не используются.
    """
    _require_key(signing_key)
    if not isinstance(token, str) or token.count(".") != 2 or len(token) > _MAX_TOKEN_LENGTH:
        raise AccessTokenError("bad_token")

    try:
        # algorithms задан кодом. Заголовок токена сам выбрать алгоритм не может.
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=[ALGORITHM],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={
                "require": list(_REQUIRED_CLAIMS),
                "verify_signature": True,
                "verify_exp": False,
                "verify_nbf": False,
                "verify_iat": False,
            },
        )
    except jwt.InvalidSignatureError:
        raise AccessTokenError("bad_signature") from None
    except jwt.InvalidAlgorithmError:
        raise AccessTokenError("bad_algorithm") from None
    except jwt.InvalidIssuerError:
        raise AccessTokenError("bad_issuer") from None
    except jwt.InvalidAudienceError:
        raise AccessTokenError("bad_audience") from None
    except jwt.MissingRequiredClaimError:
        raise AccessTokenError("missing_claim") from None
    except jwt.InvalidTokenError:
        raise AccessTokenError("bad_token") from None

    _check_claim_values(claims, _clock(now))
    return {
        "sub": claims["sub"],
        "sid": claims["sid"],
        "jti": claims["jti"],
        "iat": claims["iat"],
        "nbf": claims["nbf"],
        "exp": claims["exp"],
        "iss": claims["iss"],
        "aud": claims["aud"],
        "token_use": claims["token_use"],
    }


def _check_claim_values(claims: dict, now: int) -> None:
    for name in ("sub", "sid", "jti"):
        if not isinstance(claims.get(name), str) or claims[name].strip() == "":
            raise AccessTokenError("missing_claim")
    if not isinstance(claims.get("aud"), str):
        raise AccessTokenError("bad_audience")
    if claims.get("token_use") != TOKEN_USE_ACCESS:
        raise AccessTokenError("bad_purpose")

    iat = _timestamp(claims.get("iat"))
    nbf = _timestamp(claims.get("nbf"))
    exp = _timestamp(claims.get("exp"))
    if iat is None or nbf is None or exp is None:
        raise AccessTokenError("bad_token")
    if iat > now or nbf > now:
        raise AccessTokenError("not_yet_valid")
    if exp <= now:
        raise AccessTokenError("expired")
    if exp - iat != ACCESS_TTL_SECONDS:
        raise AccessTokenError("bad_lifetime")


def _timestamp(value) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value < 0:
        return None
    return value


def _clock(now: int | None) -> int:
    if now is None:
        return int(time.time())
    if isinstance(now, bool) or not isinstance(now, int):
        raise ValueError("Время пропуска должно быть целым числом секунд")
    return now


def _require_key(signing_key: bytes) -> None:
    if not isinstance(signing_key, bytes) or len(signing_key) != 32:
        raise ValueError("Секрет HS256 должен быть 32 байтами")


def _require_id(value: str) -> None:
    if not isinstance(value, str) or value.strip() == "" or value != value.strip():
        raise ValueError("Нужен непустой идентификатор")
