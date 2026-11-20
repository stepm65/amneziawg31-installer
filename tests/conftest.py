"""Make src/ importable for direct web.py loading during offline unit tests."""
import sys
from pathlib import Path

root = str(Path(__file__).resolve().parents[1] / 'src')
if root not in sys.path:
    sys.path.insert(0, root)

import os

# Tests never ask GitHub for the latest release (the panel does that in the background otherwise).
os.environ.setdefault('AWG31_UPDATE_CHECK', '0')
