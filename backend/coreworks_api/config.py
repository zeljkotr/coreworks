from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


BACKEND_ENV = Path(__file__).resolve().parents[1] / ".env"


class Settings(BaseSettings):
    database_url: str
    auth_secret: str

    model_config = SettingsConfigDict(
        env_file=BACKEND_ENV,
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
