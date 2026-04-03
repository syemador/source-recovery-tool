"""
Configuration management.

Loads settings from (in order of priority):
  1. Environment variables
  2. config.json in project root
  3. Hard-coded defaults
"""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_FILE = Path(__file__).parent.parent / "config.json"


@dataclass
class Config:
    ghidra_home: str = ""
    project_dir: str = ""
    github_token: str = ""
    llm_api_key: str = ""
    llm_model: str = "gpt-4o"
    llm_base_url: str = "https://api.openai.com/v1"
    max_candidates: int = 50
    # Feature ranking tunables
    min_constant_value: int = 255
    max_constant_value: int = 0xFFFFFFFFFFFFFFFF
    common_constants_blocklist: list = field(default_factory=lambda: [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 16, 32, 64, 128, 256, 512, 1024,
        0xFF, 0xFFFF, 0xFFFFFFFF, 0x80000000, 0x7FFFFFFF,
        0x100, 0x200, 0x400, 0x800, 0x1000,
    ])

    @classmethod
    def load(cls) -> "Config":
        """Load configuration from file and environment variables."""
        cfg = cls()

        # Load from config.json
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE) as f:
                    data = json.load(f)
                for key, value in data.items():
                    if hasattr(cfg, key):
                        setattr(cfg, key, value)
            except (json.JSONDecodeError, OSError) as e:
                print(f"[WARN] Could not parse {CONFIG_FILE}: {e}")

        # Environment overrides
        env_map = {
            "GHIDRA_HOME": "ghidra_home",
            "GHIDRA_PROJECT_DIR": "project_dir",
            "GITHUB_TOKEN": "github_token",
            "LLM_API_KEY": "llm_api_key",
            "OPENAI_API_KEY": "llm_api_key",
            "LLM_MODEL": "llm_model",
            "LLM_BASE_URL": "llm_base_url",
        }
        for env_var, attr in env_map.items():
            val = os.environ.get(env_var)
            if val:
                setattr(cfg, attr, val)

        # Default project dir
        if not cfg.project_dir:
            cfg.project_dir = str(Path(__file__).parent.parent / "ghidra_projects")

        return cfg

    def save(self, path: str | None = None):
        """Save current config to JSON."""
        target = Path(path) if path else CONFIG_FILE
        data = {
            "ghidra_home": self.ghidra_home,
            "project_dir": self.project_dir,
            "github_token": self.github_token,
            "llm_api_key": self.llm_api_key,
            "llm_model": self.llm_model,
            "llm_base_url": self.llm_base_url,
            "max_candidates": self.max_candidates,
        }
        with open(target, "w") as f:
            json.dump(data, f, indent=2)
