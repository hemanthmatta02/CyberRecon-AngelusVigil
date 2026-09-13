"""
©AngelaMos | 2026
config.py

Pydantic-settings application configuration loaded from
environment variables and .env file

Defines the Settings model with defaults for: server
(host 0.0.0.0, port 8000, debug, log_level), database
(postgresql+asyncpg URL), Redis URL, GeoIP MaxMind
database path, nginx log path, pipeline queue sizes
(raw 1000, parsed 500, feature 200, alert 100), batch
settings (size 32, timeout 50ms), and ML configuration
(model_dir, detection_mode, ensemble weights for
autoencoder/random-forest/isolation-forest at 0.40/0.40
/0.20 with model_validator enforcing sum-to-1.0,
ae_threshold_percentile 99.5, MLflow tracking URI).
Exports a module-level singleton settings instance

Connects to:
  factory.py        - consumed in lifespan and create_app
  __main__.py       - server host/port/reload
  core/ingestion/   - queue sizes, log path
  core/detection/   - model_dir, ensemble weights
  core/enrichment/  - geoip_db_path
"""

from typing import Self
from urllib.parse import urlparse

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application configuration loaded from environment variables.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    app_name: str = "CyberSentinel"
    env: str = "development"
    debug: bool = False
    host: str = "0.0.0.0"
    port: int = 8000
    api_key: str = ""
    auth_secret: str = ""
    resend_api_key: str = ""
    email_from: str = ""
    frontend_url: str = "http://localhost:5173"
    email_verification_expires_minutes: int = 30
    email_verification_required: bool = False
    allow_demo_auth: bool = False
    allow_public_registration: bool = True
    cors_origins: str = ""
    log_level: str = "INFO"

    database_url: str = "postgresql+asyncpg://vigil:changeme@localhost:5432/cybersentinel"

    @field_validator("database_url", mode="before")
    @classmethod
    def _normalize_database_url(cls, value: object) -> str:
        """Normalize provider URLs to the async SQLAlchemy driver."""
        url = str(value)
        if url.startswith("postgres://"):
            return "postgresql+asyncpg://" + url[len("postgres://"):]
        if url.startswith("postgresql://"):
            return "postgresql+asyncpg://" + url[len("postgresql://"):]
        return url

    redis_url: str = "redis://localhost:6379"

    geoip_db_path: str = "/usr/share/GeoIP/GeoLite2-City.mmdb"

    nginx_log_path: str = "/var/log/nginx/access.log"

    raw_queue_size: int = 1000
    parsed_queue_size: int = 500
    feature_queue_size: int = 200
    alert_queue_size: int = 100

    batch_size: int = 32
    batch_timeout_ms: int = 50

    model_dir: str = "data/models"
    detection_mode: str = "rules"
    ensemble_weight_ae: float = 0.40
    ensemble_weight_rf: float = 0.40
    ensemble_weight_if: float = 0.20
    ae_threshold_percentile: float = 99.5
    mlflow_tracking_uri: str = "file:./mlruns"

    # Optional local-only analysis; disabled by default outside local .env files.
    ollama_enabled: bool = False
    ollama_base_url: str = ""
    ollama_model: str = "qwen2.5:7b"
    ollama_timeout_seconds: float = 45.0
    ollama_max_input_bytes: int = 120_000
    ollama_max_output_tokens: int = 1_500

    def cors_origin_list(self) -> list[str]:
        """Return configured browser origins as a normalized list."""
        return [origin.strip().rstrip("/") for origin in self.cors_origins.split(",") if origin.strip()]

    def validate_ollama_runtime(self) -> None:
        """Allow only a local Ollama listener; never a public model endpoint."""
        if not self.ollama_enabled:
            return
        if self.env.lower() == "production":
            raise ValueError("OLLAMA_ENABLED must be false in production")
        if not self.ollama_base_url.strip():
            raise ValueError("OLLAMA_BASE_URL is required when OLLAMA_ENABLED is true")
        parsed = urlparse(self.ollama_base_url.strip())
        local_hosts = {"localhost", "127.0.0.1", "::1", "host.docker.internal"}
        if (parsed.scheme not in {"http", "https"}
                or parsed.hostname not in local_hosts
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
                or parsed.path not in {"", "/"}):
            raise ValueError("OLLAMA_BASE_URL must point to a local Ollama listener")
        if self.ollama_timeout_seconds <= 0 or self.ollama_timeout_seconds > 300:
            raise ValueError("OLLAMA_TIMEOUT_SECONDS must be between 0 and 300")
        if self.ollama_max_input_bytes < 1024 or self.ollama_max_input_bytes > 2_000_000:
            raise ValueError("OLLAMA_MAX_INPUT_BYTES is outside the safe range")
        if self.ollama_max_output_tokens < 128 or self.ollama_max_output_tokens > 16_000:
            raise ValueError("OLLAMA_MAX_OUTPUT_TOKENS is outside the safe range")

    def validate_runtime(self) -> None:
        """Reject unsafe production defaults before the app starts."""
        self.validate_ollama_runtime()
        if self.env.lower() != "production":
            return
        if len(self.auth_secret) < 32:
            raise ValueError("AUTH_SECRET must be at least 32 characters in production")
        if self.allow_demo_auth:
            raise ValueError("ALLOW_DEMO_AUTH must be false in production")
        if self.allow_public_registration:
            raise ValueError("ALLOW_PUBLIC_REGISTRATION must be false in production")
        if not self.cors_origin_list():
            raise ValueError("CORS_ORIGINS must be configured in production")

    @model_validator(mode="after")
    def _check_ensemble_weights(self) -> Self:
        """
        Validate that ensemble weights sum to 1.0
        """
        total = (
            self.ensemble_weight_ae
            + self.ensemble_weight_rf
            + self.ensemble_weight_if
        )
        if abs(total - 1.0) > 1e-6:
            raise ValueError(
                f"Ensemble weights must sum to 1.0, got {total:.6f}"
            )
        return self


settings = Settings()
