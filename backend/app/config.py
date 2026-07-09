from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite+aiosqlite:///./mcpeek.db"
    MAX_TARGET_LENGTH: int = 2048
    MAX_INLINE_CONTENT_BYTES: int = 500_000
    MAX_REMOTE_BYTES: int = 1_000_000
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    CORS_ORIGINS: str = "http://localhost:3000"
    RATE_LIMIT_PER_MINUTE: int = 10
    ALLOW_LOCAL_PATH_SCANS: bool = False
    ALLOW_PRIVATE_NETWORK_SCANS: bool = False
    OPENROUTER_API_KEY: str = ""
    SKILLCLOAK_ENTROPY_THRESHOLD: float = 5.5

    model_config = {"env_prefix": "MCPEEK_"}


settings = Settings()
