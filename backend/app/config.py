from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite+aiosqlite:///./mcpeek.db"
    SCAN_TIMEOUT: int = 120
    MAX_CONCURRENT_SCANS: int = 10
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    CORS_ORIGINS: str = "http://localhost:3000"
    RATE_LIMIT_PER_MINUTE: int = 10

    model_config = {"env_prefix": "MCPEEK_"}


settings = Settings()
