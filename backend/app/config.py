from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite+aiosqlite:///./mcpeek.db"
    TURSO_DATABASE_URL: str = ""
    TURSO_AUTH_TOKEN: str = ""
    MAX_TARGET_LENGTH: int = 2048
    MAX_INLINE_CONTENT_BYTES: int = 500_000
    MAX_REMOTE_BYTES: int = 1_000_000
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    CORS_ORIGINS: str = "http://localhost:3000"
    RATE_LIMIT_PER_MINUTE: int = 10
    ALLOW_LOCAL_PATH_SCANS: bool = False
    ALLOW_PRIVATE_NETWORK_SCANS: bool = False
    ADMIN_API_KEY: str = ""
    OPENROUTER_API_KEY: str = ""
    NVIDIA_NIM_API_KEY: str = ""
    NVIDIA_NIM_BASE_URL: str = "https://integrate.api.nvidia.com/v1"
    AI_MODEL_DETECTION: str = "meta/llama-3.3-70b-instruct"
    AI_MODEL_ENRICHMENT: str = "nvidia/nemotron-nano-12b-v2"
    AI_MODEL_DEFENSE: str = "qwen/qwen3-8b"
    SKILLCLOAK_ENTROPY_THRESHOLD: float = 5.5

    model_config = {"env_prefix": "MCPEEK_"}


settings = Settings()

# Allow separate TURSO_DATABASE_URL + TURSO_AUTH_TOKEN (Turso convention)
if settings.TURSO_DATABASE_URL and not settings.DATABASE_URL.startswith("libsql"):
    token_suffix = f"?authToken={settings.TURSO_AUTH_TOKEN}" if settings.TURSO_AUTH_TOKEN else ""
    settings.DATABASE_URL = f"{settings.TURSO_DATABASE_URL}{token_suffix}"
