"""
Source adapters for Trustfall Lite.

Each adapter is responsible for understanding one local-ecosystem
layout and producing normalized ModelGroup objects that the
verification core can consume without further source-specific logic.

v0.2 implements:
  HFCacheAdapter  — Hugging Face cache layout
  OllamaAdapter   — Ollama manifest + content-addressed blob layout
  PathAdapter     — arbitrary filesystem path or directory tree

v0.3+ stubs (raise NotImplementedError until implemented):
  LMStudioAdapter
"""

from .base import SourceAdapter
from .hf_cache import HFCacheAdapter
from .lmstudio import LMStudioAdapter
from .ollama import OllamaAdapter
from .path import PathAdapter

__all__ = [
    "SourceAdapter",
    "HFCacheAdapter",
    "PathAdapter",
    "OllamaAdapter",
    "LMStudioAdapter",
]
