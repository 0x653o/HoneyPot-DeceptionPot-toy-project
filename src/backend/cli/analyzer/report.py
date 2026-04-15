"""
Report Generator — Text and JSON report output.

Produces two formats:
1. Text report (human-readable, terminal-friendly)
2. JSON report (machine-readable, API/dashboard-friendly)
"""

import json
from typing import Optional

from .parser import AnalysisResult


def generate_text_report(
    result: AnalysisResult,
    top_n: int = 10,
) -> str:
    """
    Generate a human-readable text report.
    
    Args:
        result: AnalysisResult from the parser.
        top_n: Number of top entries to show.
        
    Returns:
        Formatted text report string.
    """
    lines = []

    lines.append("=" * 50)
    lines.append(" HONEYPOT LOG ANALYSIS REPORT")
    lines.append("=" * 50)
    lines.append("")
    lines.append(f"Total connections logged:  {result.total_connections}")
    lines.append(f"Total unique attackers:    {result.total_unique_ips}")
    lines.append("")

    # Protocol breakdown
    lines.append("--- Protocol Breakdown ---")
    for protocol, count in result.protocol_counts.most_common():
        pct = (count / result.total_connections * 100) if result.total_connections else 0
        bar = "█" * int(pct / 5)
        lines.append(f"  {protocol:<8} : {count:>5}  ({pct:5.1f}%)  {bar}")
    lines.append("")

    # Top payloads
    n_payloads = min(top_n, len(result.overall_payloads))
    lines.append(f"--- Top {n_payloads} Data Payloads ---")
    if not result.overall_payloads:
        lines.append("  No data payloads logged.")
    else:
        for payload, count in result.overall_payloads.most_common(top_n):
            display = (payload[:60] + "...") if len(payload) > 60 else payload
            lines.append(f"  {count:<5} : {display}")
    lines.append("")

    # Top credentials
    if result.overall_credentials:
        cred_counts = {}
        for cred in result.overall_credentials:
            key = f"{cred['username']}:{cred['password']}"
            cred_counts[key] = cred_counts.get(key, 0) + 1

        sorted_creds = sorted(
            cred_counts.items(), key=lambda x: x[1], reverse=True
        )
        n_creds = min(top_n, len(sorted_creds))
        lines.append(f"--- Top {n_creds} Credential Pairs ---")
        for cred_pair, count in sorted_creds[:top_n]:
            lines.append(f"  {count:<5} : {cred_pair}")
        lines.append("")

    # Top attacker IPs
    sorted_ips = sorted(
        result.ip_summaries.values(),
        key=lambda s: s.total_connections,
        reverse=True,
    )
    n_ips = min(top_n, len(sorted_ips))
    lines.append(f"--- Top {n_ips} Attacker IPs ---")
    if not sorted_ips:
        lines.append("  No IP addresses logged.")
    else:
        for ip_summary in sorted_ips[:top_n]:
            lines.append("")
            protocols_str = ",".join(sorted(ip_summary.protocols_used))
            lines.append(
                f"  {ip_summary.ip:<18} : "
                f"{ip_summary.total_connections} attempts "
                f"[{protocols_str}]"
            )

            if ip_summary.info:
                lines.append(
                    f"    Host: {ip_summary.info.get('hostname', 'N/A')}"
                )
                lines.append(
                    f"    Loc:  {ip_summary.info.get('location', 'N/A')}"
                )

            lines.append(
                f"    First: {ip_summary.first_seen}  "
                f"Last: {ip_summary.last_seen}"
            )

            # Top payloads for this IP
            if ip_summary.payload_counter:
                lines.append("    Top Payloads:")
                for payload, count in ip_summary.payload_counter.most_common(3):
                    display = (
                        (payload[:50] + "...")
                        if len(payload) > 50
                        else payload
                    )
                    lines.append(f"      {count:<4} : {display}")

            # Credentials for this IP
            if ip_summary.credentials:
                lines.append("    Credentials Tried:")
                seen = set()
                for user, pwd in ip_summary.credentials[:5]:
                    pair = f"{user}:{pwd}"
                    if pair not in seen:
                        lines.append(f"      {pair}")
                        seen.add(pair)

    lines.append("")
    lines.append("=" * 50)
    lines.append("End of Report")

    return "\n".join(lines)


def generate_json_report(
    result: AnalysisResult,
    top_n: int = 20,
) -> dict:
    """
    Generate a machine-readable JSON report.
    
    Args:
        result: AnalysisResult from the parser.
        top_n: Number of top entries to include.
        
    Returns:
        Dict suitable for json.dumps().
    """
    sorted_ips = sorted(
        result.ip_summaries.values(),
        key=lambda s: s.total_connections,
        reverse=True,
    )

    report = {
        "metadata": {
            "total_connections": result.total_connections,
            "total_unique_attackers": result.total_unique_ips,
            "protocol_breakdown": dict(result.protocol_counts),
        },
        "top_payloads": [
            {"payload": p, "count": c}
            for p, c in result.overall_payloads.most_common(top_n)
        ],
        "top_credentials": _aggregate_credentials(
            result.overall_credentials, top_n
        ),
        "attackers": [
            _ip_summary_to_dict(s)
            for s in sorted_ips
        ],
        "timeline": result.timeline[:1000],  # Cap timeline
    }

    return report


def _aggregate_credentials(credentials: list, top_n: int) -> list:
    """Aggregate and count unique credential pairs."""
    counts = {}
    for cred in credentials:
        key = f"{cred['username']}:{cred['password']}"
        if key not in counts:
            counts[key] = {
                "username": cred["username"],
                "password": cred["password"],
                "count": 0,
                "protocols": set(),
            }
        counts[key]["count"] += 1
        counts[key]["protocols"].add(cred["protocol"])

    sorted_creds = sorted(
        counts.values(), key=lambda x: x["count"], reverse=True
    )

    return [
        {
            "username": c["username"],
            "password": c["password"],
            "count": c["count"],
            "protocols": list(c["protocols"]),
        }
        for c in sorted_creds[:top_n]
    ]


def _ip_summary_to_dict(summary) -> dict:
    """Convert an IPSummary to a JSON-friendly dict."""
    return {
        "ip": summary.ip,
        "total_connections": summary.total_connections,
        "protocols": list(summary.protocols_used),
        "first_seen": summary.first_seen,
        "last_seen": summary.last_seen,
        "hostname": summary.info.get("hostname", "N/A") if summary.info else "N/A",
        "location": summary.info.get("location", "N/A") if summary.info else "N/A",
        "country_code": summary.info.get("country_code", "N/A") if summary.info else "N/A",
        "latitude": summary.info.get("latitude") if summary.info else None,
        "longitude": summary.info.get("longitude") if summary.info else None,
        "top_payloads": [
            {"payload": p, "count": c}
            for p, c in summary.payload_counter.most_common(10)
        ],
        "credentials": [
            {"username": u, "password": p}
            for u, p in summary.credentials[:20]
        ],
    }


def print_text_report(result: AnalysisResult, top_n: int = 10):
    """Print the text report to stdout."""
    print(generate_text_report(result, top_n))


def print_json_report(result: AnalysisResult, top_n: int = 20):
    """Print the JSON report to stdout."""
    print(json.dumps(generate_json_report(result, top_n), indent=2))
