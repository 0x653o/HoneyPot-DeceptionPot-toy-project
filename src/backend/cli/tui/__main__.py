"""
TUI — Entry point for running as a module.

Usage:
    python -m tui
    python -m tui --api http://localhost:9090
"""

import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        description="Honeypot TUI — Terminal-based monitoring dashboard.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--api",
        default="http://localhost:9090",
        help="URL of the management API.\nDefault: http://localhost:9090",
    )
    parser.add_argument(
        "--api-key",
        default="",
        help="Management API Key",
    )
    args = parser.parse_args()

    try:
        from .app import HoneypotTUI
        app = HoneypotTUI(api_url=args.api, api_key=args.api_key)
        app.run()
    except ImportError as e:
        print(
            f"Error: Missing dependency: {e}\n"
            f"Install with: pip install textual httpx",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
