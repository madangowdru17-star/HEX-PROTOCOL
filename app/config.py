import os
from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    # App
    APP_NAME: str = "License Admin Panel"
    DEBUG: bool = False
    SECRET_KEY: str = "your-secret-key-change-me-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Database - default SQLite, override with PostgreSQL in production
    DATABASE_URL: str = "sqlite:///./license_admin.db"

    # RSA keys for signing responses
    PRIVATE_KEY_PATH: Optional[str] = None
    PUBLIC_KEY_PATH: Optional[str] = None
    PRIVATE_KEY_PEM: Optional[str] = None
    PUBLIC_KEY_PEM: Optional[str] = None

    # Rate limiting
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_PER_MINUTE: int = 60

    # CORS
    CORS_ORIGINS: list = ["*"]

    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()