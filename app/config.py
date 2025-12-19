from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    REDIS_URL: str = "redis://localhost:6379/0"
    QDRANT_URL: str = "http://localhost:6333"
    BROWSERLESS_URL: str = "ws://localhost:3000"

    class Config:
        env_file = ".env"

settings = Settings()
