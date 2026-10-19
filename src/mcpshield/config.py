"""Configuration: `config.yaml` loaded once into a typed `Settings`, with MCPSHIELD_* env overrides."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, model_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_ENV = "MCPSHIELD_CONFIG"


def config_path() -> Path:
    return Path(os.environ.get(CONFIG_ENV, REPO_ROOT / "config.yaml"))


class PathsConfig(BaseModel):
    data_dir: Path
    synthetic_dir: Path
    sandbox_dir: Path
    scenarios_dir: Path
    policies_file: Path
    threat_kb_dir: Path
    db_path: Path
    chroma_dir: Path
    eval_dir: Path
    figures_dir: Path
    results_md: Path
    log_file: Path

    @model_validator(mode="after")
    def _absolutize(self) -> PathsConfig:
        for name in type(self).model_fields:
            value: Path = getattr(self, name)
            if not value.is_absolute():
                object.__setattr__(self, name, REPO_ROOT / value)
        return self


class LLMConfig(BaseModel):
    backend: Literal["mock", "ollama", "groq"]
    ollama_url: str
    judge_model: str
    fast_model: str
    groq_url: str
    groq_agent_model: str
    groq_judge_model: str
    temperature: float
    sample_temperature: float
    timeout_s: float
    max_retries: int


class RAGConfig(BaseModel):
    embedder: Literal["auto", "sentence-transformers", "hashing"]
    reranker: Literal["auto", "cross-encoder", "lexical"]
    embed_model: str
    rerank_model: str
    hashing_dim: int
    collection: str
    chunk_size: int
    chunk_overlap: int
    candidates: int
    top_k: int
    rrf_k: int


class Thresholds(BaseModel):
    block: float
    escalate: float
    sanitize: float


class RiskConfig(BaseModel):
    grey_zone: tuple[float, float]
    thresholds: Thresholds
    self_consistency_n: int
    reputation_weight: float
    reputation_saturation: int
    weights: dict[str, float]


class AblationConfig(BaseModel):
    registry_auditor: bool = True
    intent_verifier: bool = True
    output_sanitizer: bool = True
    llm_checks: bool = True
    rag: bool = True


class ShieldConfig(BaseModel):
    enabled: bool
    sanitize_mode: Literal["spotlight", "quarantine"]
    escalate_counts_as_blocked: bool
    tool_refresh_interval_s: float
    ablation: AblationConfig
    disabled_detectors: list[str] = Field(default_factory=list)


class ServerEntry(BaseModel):
    module: str


class ServersConfig(BaseModel):
    finance: ServerEntry
    utility: ServerEntry
    namespace_sep: str


class DataConfig(BaseModel):
    seed: int
    n_invoices: int


class EvalConfig(BaseModel):
    ablations: list[str]
    backends: list[Literal["mock", "ollama"]]
    max_agent_steps: int


class LoggingConfig(BaseModel):
    level: str
    json_format: bool = Field(alias="json")


class ScannerConfig(BaseModel):
    timeout_s: float
    max_tools: int
    max_description_chars: int
    max_input_chars: int
    allow_private_urls: bool
    demo_servers_file: Path

    @model_validator(mode="after")
    def _absolutize(self) -> ScannerConfig:
        if not self.demo_servers_file.is_absolute():
            object.__setattr__(self, "demo_servers_file", REPO_ROOT / self.demo_servers_file)
        return self


class ApiConfig(BaseModel):
    allowed_origin_regex: str
    rate_limit_per_minute: int
    agent_rate_limit_per_minute: int
    max_text_chars: int
    max_task_chars: int
    agent_timeout_s: float
    analyze_concurrency: int


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="MCPSHIELD_", env_nested_delimiter="__", extra="ignore")

    paths: PathsConfig
    llm: LLMConfig
    rag: RAGConfig
    risk: RiskConfig
    shield: ShieldConfig
    servers: ServersConfig
    data: DataConfig
    eval: EvalConfig
    logging: LoggingConfig
    api: ApiConfig
    scanner: ScannerConfig

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (init_settings, env_settings, YamlConfigSettingsSource(settings_cls, yaml_file=config_path()))


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
