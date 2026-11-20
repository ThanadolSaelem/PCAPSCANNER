"""Allow executing the standalone package via `python -m tier1_inference`."""
from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
