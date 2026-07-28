from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="PROBESTORE_", extra="ignore"
    )

    database_url: str = "postgresql+asyncpg://probestore:probestore@localhost:5432/probestore"
    api_token: str = "change-me"
    stale_after_seconds: int = 300
    echo_sql: bool = False


@lru_cache
def get_settings() -> Settings:
    return Settings()
