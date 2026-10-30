import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Principal:
    user_id: str
    role: str
    department: str


@dataclass(frozen=True)
class Settings:
    database_url: str
    redis_url: str | None
    api_keys: dict[str, Principal]
    rate_limit: int
    rate_window_seconds: int
    upstream_base_url: str | None
    upstream_api_key: str | None
    request_timeout_seconds: float


def load_settings() -> Settings:
    key_entries = os.getenv(
        "API_KEYS", "local-dev-key:demo-user:admin:engineering"
    )
    api_keys: dict[str, Principal] = {}
    for entry in key_entries.split(","):
        parts = entry.strip().split(":")
        if len(parts) != 4 or not all(parts):
            raise ValueError(
                "API_KEYS entries must use key:user_id:role:department format"
            )
        key, user_id, role, department = parts
        api_keys[key] = Principal(user_id, role, department)

    return Settings(
        database_url=os.getenv("DATABASE_URL", "sqlite:///./data/audit.db"),
        redis_url=os.getenv("REDIS_URL") or None,
        api_keys=api_keys,
        rate_limit=int(os.getenv("RATE_LIMIT", "30")),
        rate_window_seconds=int(os.getenv("RATE_WINDOW_SECONDS", "60")),
        upstream_base_url=os.getenv("UPSTREAM_BASE_URL", "").rstrip("/") or None,
        upstream_api_key=os.getenv("UPSTREAM_API_KEY") or None,
        request_timeout_seconds=float(os.getenv("REQUEST_TIMEOUT_SECONDS", "30")),
    )


settings = load_settings()
