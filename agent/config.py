"""
Configuration management for the AI agent.
"""
import os
from typing import Dict, Any, Optional
from pydantic_settings import BaseSettings
from pydantic import Field
from dotenv import load_dotenv

class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    # Required fields for local mode
    openai_api_key: str = Field(..., env="OPENAI_API_KEY")
    openai_model: str = Field("gpt-4.1-nano-2025-04-14", env="OPENAI_MODEL")
    log_level: str = Field("INFO", env="LOG_LEVEL")
    log_file: str = Field("agent.log", env="LOG_FILE")
    
    # Additional fields for server mode
    agentarena_api_key: Optional[str] = Field(None, env="AGENTARENA_API_KEY")
    webhook_auth_token: Optional[str] = Field(None, env="WEBHOOK_AUTH_TOKEN")
    data_dir: Optional[str] = Field("./data", env="DATA_DIR")
    enable_localtunnel: bool = Field(False, env="ENABLE_LOCALTUNNEL")
    localtunnel_subdomain: Optional[str] = Field(None, env="LOCALTUNNEL_SUBDOMAIN")
    localtunnel_host: str = Field("https://localtunnel.me", env="LOCALTUNNEL_HOST")
    localtunnel_command: str = Field("npx --yes localtunnel", env="LOCALTUNNEL_COMMAND")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

def load_config() -> Settings:
    """Load and return application configuration."""
    load_dotenv(override=True)
    return Settings() 
