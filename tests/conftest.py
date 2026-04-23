from __future__ import annotations

import os
import sys

import pytest
import yaml


ROOT = os.path.dirname(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


@pytest.fixture()
def base_dir() -> str:
    return ROOT


@pytest.fixture()
def test_cfg(base_dir: str) -> dict:
    with open(os.path.join(base_dir, "config.test.yaml"), "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}
