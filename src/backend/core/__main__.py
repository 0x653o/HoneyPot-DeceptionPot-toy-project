"""
Honeypot — Entry point for running as a module.

Usage:
    python -m honeypot
    python -m honeypot --config /path/to/config.yaml
"""

import argparse
import asyncio
import sys

from .core import run_server


def main():
    parser = argparse.ArgumentParser(
        description="Multi-protocol honeypot with per-connection sandboxing.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "-c", "--config",
        default="config.yaml",
        help="Path to config.yaml file.\nDefault: config.yaml",
    )
    args = parser.parse_args()

    print(r"""
    ╔══════════════════════════════════════════╗
    ║        🍯 HONEYPOT SERVER v1.0.0        ║
    ║                                          ║
    ║   Multi-Protocol | Sandboxed | Logging   ║
    ╚══════════════════════════════════════════╝
    """)

    try:
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(
                asyncio.WindowsSelectorEventLoopPolicy()
            )
        asyncio.run(run_server(args.config))
    except KeyboardInterrupt:
        print("\nHoneypot shut down by user.")
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
