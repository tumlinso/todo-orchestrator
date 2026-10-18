"""Small bootstrap command line; workflow commands are not available yet."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from todo_orchestrator import __version__


def _parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        prog="todo",
        description="Standalone Todo Orchestrator. Workflow commands are not available yet.",
        epilog="This bootstrap provides only help and version information.",
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Show bootstrap help or version information and return an exit status."""
    parser = _parser()
    parser.add_argument(
        "--version",
        action="version",
        version=f"todo {__version__}",
    )
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        parser.print_help()
        return 0
    parser.parse_args(arguments)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
