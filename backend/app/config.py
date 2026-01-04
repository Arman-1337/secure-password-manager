"""
Application Configuration
"""
from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    """Application settings."""
    
    # App Info
    APP_NAME: str = "Secure Password Manager"
    APP_VERSION: str = "1.0.0"
    
    # Security
    SECRET_KEY: str = "change-this-to-a-very-long-random-string-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Session
    SESSION_TIMEOUT_MINUTES: int = 15
    
    # Password Policy
    MIN_PASSWORD_LENGTH: int = 8
    MAX_PASSWORD_LENGTH: int = 128
    REQUIRE_SPECIAL_CHAR: bool = True
    REQUIRE_DIGIT: bool = True
    REQUIRE_UPPERCASE: bool = True
    REQUIRE_LOWERCASE: bool = True
    
    # Database
    DATABASE_URL: str = "sqlite:///./password_manager.db"
    
    # CORS
    ALLOWED_ORIGINS: list = [
        "http://localhost:3000",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000"
    ]
    
    class Config:
        env_file = ".env"

settings = Settings()
