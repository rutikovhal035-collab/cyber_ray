"""
Application configuration settings
"""

from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
    # API Configuration
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    DEBUG: bool = True
    
    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:5173", "http://localhost:3000"]
    
    # CAPEv2 Configuration
    CAPE_API_URL: str = "http://localhost:8000"
    CAPE_API_TOKEN: str = ""
    
    # MongoDB Configuration
    MONGODB_URL: str = "mongodb://localhost:27017"
    MONGODB_DB_NAME: str = "malware_sandbox"
    
    # Redis Configuration
    REDIS_URL: str = "redis://localhost:6379"
    
    # File Upload
    UPLOAD_DIR: str = "./uploads"
    MAX_FILE_SIZE: int = 50 * 1024 * 1024  # 50MB
    
    # YARA Rules
    YARA_RULES_DIR: str = "./yara_rules"
    
    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
