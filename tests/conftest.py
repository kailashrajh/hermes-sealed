"""Load the store module by path so the suite runs without the Hermes runtime."""

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODULE = ROOT / "plugins" / "sealed" / "store.py"

spec = importlib.util.spec_from_file_location("sealed_store", MODULE)
module = importlib.util.module_from_spec(spec)
sys.modules["sealed_store"] = module
spec.loader.exec_module(module)
