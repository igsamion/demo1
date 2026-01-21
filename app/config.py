import os
from dataclasses import dataclass


def _env(name: str, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if value is None:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    return int(value)


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    app_host: str
    app_port: int
    app_env: str
    session_secret: str
    csrf_secret: str
    session_idle_timeout_min: int
    session_absolute_timeout_h: int
    session_cookie_secure: bool

    ldap_url: str
    ldap_base_dn: str
    ldap_bind_dn: str
    ldap_bind_password: str
    ldap_user_filter: str
    ldap_use_upn: bool
    ldap_attrs: list[str]
    ldap_ca_cert: str | None
    ldap_timeout_seconds: int

    rate_limit_login_per_min: int
    rate_limit_chat_per_min: int
    lockout_threshold: int
    lockout_window_min: int
    lockout_duration_min: int
    required_ad_groups: list[str]

    ollama_url: str
    ollama_model: str
    ollama_timeout_seconds: int
    chat_context_messages: int


def load_settings() -> Settings:
    return Settings(
        app_host=os.getenv("APP_HOST", "0.0.0.0"),
        app_port=_env_int("APP_PORT", 8000),
        app_env=os.getenv("APP_ENV", "development"),
        session_secret=_env("SESSION_SECRET"),
        csrf_secret=_env("CSRF_SECRET"),
        session_idle_timeout_min=_env_int("SESSION_IDLE_TIMEOUT_MIN", 20),
        session_absolute_timeout_h=_env_int("SESSION_ABSOLUTE_TIMEOUT_H", 8),
        session_cookie_secure=_env_bool("SESSION_COOKIE_SECURE", False),
        ldap_url=os.getenv("LDAP_URL", "ldaps://ad.example.org:636"),
        ldap_base_dn=_env("LDAP_BASE_DN"),
        ldap_bind_dn=_env("LDAP_BIND_DN"),
        ldap_bind_password=_env("LDAP_BIND_PASSWORD"),
        ldap_user_filter=os.getenv(
            "LDAP_USER_FILTER", "(&(objectClass=user)(sAMAccountName={username}))"
        ),
        ldap_use_upn=_env_bool("LDAP_USE_UPN", False),
        ldap_attrs=[
            attr.strip()
            for attr in os.getenv(
                "LDAP_ATTRS", "displayName,mail,memberOf,objectGUID"
            ).split(",")
            if attr.strip()
        ],
        ldap_ca_cert=os.getenv("LDAP_CA_CERT"),
        ldap_timeout_seconds=_env_int("LDAP_TIMEOUT_SECONDS", 5),
        rate_limit_login_per_min=_env_int("RATE_LIMIT_LOGIN_PER_MIN", 5),
        rate_limit_chat_per_min=_env_int("RATE_LIMIT_CHAT_PER_MIN", 30),
        lockout_threshold=_env_int("LOCKOUT_THRESHOLD", 5),
        lockout_window_min=_env_int("LOCKOUT_WINDOW_MIN", 15),
        lockout_duration_min=_env_int("LOCKOUT_DURATION_MIN", 30),
        required_ad_groups=[
            g.strip()
            for g in os.getenv("REQUIRED_AD_GROUP_DN", "").split(",")
            if g.strip()
        ],
        ollama_url=os.getenv("OLLAMA_URL", "http://127.0.0.1:11434"),
        ollama_model=os.getenv("OLLAMA_MODEL", "llama3"),
        ollama_timeout_seconds=_env_int("OLLAMA_TIMEOUT_SECONDS", 30),
        chat_context_messages=_env_int("CHAT_CONTEXT_MESSAGES", 8),
    )
