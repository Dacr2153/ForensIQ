# FILE: src/forensiq/__main__.py
"""Entry point for `python -m forensiq`.

Allows running forensiq as a module:
    python -m forensiq analyze /path/to/dump.raw
    python -m forensiq check
    python -m forensiq --help
"""

from forensiq.cli import app

if __name__ == "__main__":
    app()
