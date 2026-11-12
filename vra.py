"""Quick-start runner: python vra.py PATH (no pip installation required)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / 'src'))
from viento_resource_analyzer.cli import main  # noqa: E402

if __name__ == '__main__':
    raise SystemExit(main())
