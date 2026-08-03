"""Application configuration loaded from environment variables."""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AEGISX_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    http_host: str = "0.0.0.0"
    http_port: int = 8080
    grpc_port: int = 50051

    chroma_path: str = "/var/lib/aegisx/chroma"
    vectorstore_enabled: bool = True

    abuseipdb_key: str = ""
    abuseipdb_url: str = "https://api.abuseipdb.com/api/v2/check"

    vt_key: str = ""
    otx_base: str = "https://otx.alienvault.com/api/v1"
    threatfox_url: str = "https://threatfox-api.abuse.ch/api/v1/"

    shadowpot_grpc: str = ""
    shadowpot_token: str = ""
    report_dir: str = "/var/lib/aegisx/reports"
    fim_ipc: str = "/var/run/aegisx-fim.sock"
    fim_log: str = ""

    ml_enabled: bool = True
    ttl_seconds: int = 300
    aggregator_cve_enrich: bool = False

    decoys_http_ports: str = "8080"
    decoys_ssh_ports: str = "2222"
    decoys_mysql_ports: str = "3306"

    def parse_ports(self, raw: str) -> list[int]:
        return [int(p) for p in raw.split(",") if p.strip().isdigit()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
