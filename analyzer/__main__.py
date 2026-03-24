"""
Analyzer — Entry point for running as a module.

Usage:
    python -m analyzer
    python -m analyzer --db data/honeypot.db
    python -m analyzer --log data/honeypot.log
    python -m analyzer --json
"""

import argparse
import sys
import os

from .parser import parse_log_file, parse_log_from_db
from .enrichment import enrich_analysis_result
from .report import print_text_report, print_json_report


def main():
    parser = argparse.ArgumentParser(
        description="Honeypot Log Analyzer — Generate intelligence reports.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--db",
        default="data/honeypot.db",
        help="Path to SQLite database.\nDefault: data/honeypot.db",
    )
    parser.add_argument(
        "--log",
        default=None,
        help="Path to text log file (used if --db not found).",
    )
    parser.add_argument(
        "--protocol",
        default=None,
        help="Filter by protocol (ssh, http, ftp, telnet, smtp).",
    )
    parser.add_argument(
        "--top", type=int, default=20,
        help="Number of top entries to show. Default: 20",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output JSON report instead of text.",
    )
    parser.add_argument(
        "--geoip",
        default="data/GeoLite2-City.mmdb",
        help="Path to GeoLite2-City.mmdb for IP enrichment.",
    )
    parser.add_argument(
        "--no-enrich", action="store_true",
        help="Skip IP enrichment (GeoIP + reverse DNS).",
    )
    args = parser.parse_args()

    # Parse data
    result = None
    if os.path.exists(args.db):
        print(f"[*] Parsing database: {args.db}", file=sys.stderr)
        result = parse_log_from_db(args.db, protocol_filter=args.protocol)
    elif args.log and os.path.exists(args.log):
        print(f"[*] Parsing log file: {args.log}", file=sys.stderr)
        result = parse_log_file(args.log, protocol_filter=args.protocol)
    else:
        print(
            f"Error: No data source found.\n"
            f"  Database: {args.db} (not found)\n"
            f"  Log file: {args.log or '(not specified)'}",
            file=sys.stderr,
        )
        sys.exit(1)

    if result.total_connections == 0:
        print("[!] No connections found in the data.", file=sys.stderr)
        sys.exit(0)

    # Enrich
    if not args.no_enrich:
        print(f"[*] Enriching {result.total_unique_ips} IPs...", file=sys.stderr)
        geoip_path = args.geoip if os.path.exists(args.geoip) else None
        enrich_analysis_result(result, geoip_path)

    # Output
    if args.json:
        print_json_report(result, top_n=args.top)
    else:
        print_text_report(result, top_n=args.top)


if __name__ == "__main__":
    main()
