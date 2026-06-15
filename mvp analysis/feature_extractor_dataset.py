#!/usr/bin/env python3
"""Compatibility wrapper for the moved Reservoir file-analysis extractor."""

from __future__ import annotations

import runpy
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
runpy.run_module("Reservoir.file_analysis.feature_extractor_dataset", run_name="__main__")
