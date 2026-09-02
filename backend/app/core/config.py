from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional, List


class Settings(BaseSettings):
    PROJECT_NAME: str = "MailShield Security Intelligence API"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"

    # AI Provider API Keys & Models
    GEMINI_API_KEY: Optional[str] = None
    GEMINI_MODEL: str = "gemini-2.5-flash"
    OPENAI_API_KEY: Optional[str] = None
    OPENAI_MODEL: str = "gpt-4o"
    AIML_API_KEY: Optional[str] = None

    # Threat Intelligence Provider API Keys (Optional)
    GOOGLE_API_KEY: Optional[str] = None
    GOOGLE_KEY2: Optional[str] = None
    GOOGLE_SAFE_BROWSING_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    WHOIS_API_KEY: Optional[str] = None

    # Intelligence Engine Settings
    INTEL_CACHE_TTL_SECONDS: int = 3600
    INTEL_REQUEST_TIMEOUT_SECONDS: float = 8.0
    AI_REQUEST_TIMEOUT_SECONDS: float = 12.0

    # Environment
    ENVIRONMENT: str = "development"

    # CORS
    BACKEND_CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()
