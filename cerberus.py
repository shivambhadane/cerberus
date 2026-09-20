#!/usr/bin/env python3
"""Cerberus CLI - continuous attack surface and exploitability intelligence."""

from __future__ import annotations

import argparse
import logging
import sys

from sqlalchemy import select

from core.config import load_config
from core.db import init_db, session_scope
from core.models import Asset, CveEnrichment, Finding, SourceRefresh
from core.pipeline import NotAuthorizedError, run_pipeline, start_scan
from core.profiles import PROFILES, ProfileViolation, get_profile
from enrichment.cache import refresh_global_sources


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def _find_user_id(email: str) -> str | None:
    from sqlalchemy import select

    from core.db import init_db, session_scope
    from core.models import User
    from core.ownership import normalize_email

    init_db()
    with session_scope() as session:
        return session.scalar(select(User.id).where(User.email == normalize_email(email)))


def cmd_scan(args: argparse.Namespace) -> int:
    config = load_config()
    if args.allow_private:
        config.discovery.allow_private_addresses = True
    if args.no_subdomains:
        config.discovery.subdomain_enum = False
    if args.ports:
        try:
            config.discovery.ports = [int(p) for p in args.ports.split(",") if p.strip()]
        except ValueError:
            print(f"refused: --ports must be comma-separated integers, got {args.ports!r}", file=sys.stderr)
            return 2
    try:
        profile = get_profile(args.profile or config.scanning.profile, opted_in=args.accept_profile)
    except ProfileViolation as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2

    owner_id = None
    if args.owner:
        owner_id = _find_user_id(args.owner)
        if owner_id is None:
            print(
                f"refused: no account for {args.owner!r}. Register it in the dashboard first.",
                file=sys.stderr,
            )
            return 2

    try:
        scan_id = start_scan(args.target, args.authorized, profile=profile.name, user_id=owner_id)
    except NotAuthorizedError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2

    print(f"profile: {profile.name} - {profile.description}")

    print(f"scan {scan_id} started against {args.target}")
    summary = run_pipeline(scan_id, config, profile=profile)
    print(
        f"done: {summary['assets']} assets, {summary['findings']} findings, "
        f"{summary['scored']} scored"
    )
    if summary.get("active_detections") is not None:
        print(
            f"detection: {summary.get('active_detections', 0)} active-detection finding(s); "
            f"tools: {', '.join(summary.get('tools', [])) or 'none'}"
        )
    for failure in summary.get("tool_errors", []):
        print(f"\nTOOL FAILED: {failure}", file=sys.stderr)
    if summary.get("warning"):
        print(f"\nWARNING: {summary['warning']}", file=sys.stderr)
    print("\nTop findings:")
    _print_report(args.top)
    return 0


def cmd_enrich(args: argparse.Namespace) -> int:
    init_db()
    with session_scope() as session:
        counts = refresh_global_sources(session, include_epss=not args.no_epss)
    print(f"enrichment cache refreshed: {counts['kev']} KEV records, {counts['epss']} EPSS scores")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    init_db()
    _print_report(args.top)
    return 0


def cmd_status(_: argparse.Namespace) -> int:
    init_db()
    with session_scope() as session:
        rows = session.scalars(select(SourceRefresh)).all()
        assets = len(session.scalars(select(Asset)).all())
        findings = len(session.scalars(select(Finding)).all())
        cves = len(session.scalars(select(CveEnrichment)).all())

    print(f"assets: {assets}   findings: {findings}   cached CVEs: {cves}")
    if not rows:
        print("no enrichment sources refreshed yet - run: cerberus.py enrich --refresh")
    for row in rows:
        stamp = row.last_refreshed_at.strftime("%Y-%m-%d %H:%M")
        print(f"  {row.name:6} last refreshed {stamp}  ({row.record_count} records)")
    return 0


def _print_report(limit: int) -> None:
    with session_scope() as session:
        rows = session.execute(
            select(Finding, CveEnrichment, Asset)
            .join(CveEnrichment, Finding.cve_id == CveEnrichment.cve_id)
            .join(Asset, Finding.asset_id == Asset.id)
            .where(Finding.risk_score.isnot(None))
            .order_by(Finding.risk_score.desc(), CveEnrichment.cvss_score.desc())
            .limit(limit)
        ).all()

        if not rows:
            print("  (no scored findings yet)")
            return

        print(f"  {'#':<3} {'RISK':>5}  {'CVE':<18} {'CVSS':>4} {'KEV':>4} {'EPSS':>6}  ASSET")
        for i, (finding, cve, asset) in enumerate(rows, 1):
            epss = f"{cve.epss_score:.2f}" if cve.epss_score is not None else "  -  "
            cvss = f"{cve.cvss_score:.1f}" if cve.cvss_score is not None else "  - "
            print(
                f"  {i:<3} {finding.risk_score:>5.1f}  {cve.cve_id:<18} {cvss:>4} "
                f"{'yes' if cve.kev_listed else 'no':>4} {epss:>6}  {asset.hostname}:{asset.port}"
            )
            print(f"      -> {finding.reasoning}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cerberus", description=__doc__)
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="run the full discovery -> scoring pipeline")
    scan.add_argument("--target", required=True, help="domain to scan")
    scan.add_argument(
        "--authorized",
        action="store_true",
        help="attest that you own or have written authorization to scan this target",
    )
    scan.add_argument(
        "--profile",
        choices=sorted(PROFILES),
        help="what scanners may do (default: the profile in config.yaml)",
    )
    scan.add_argument(
        "--accept-profile",
        action="store_true",
        help="acknowledge a more intrusive profile that requires explicit opt-in",
    )
    scan.add_argument(
        "--owner",
        metavar="EMAIL",
        help="attach the scan to this dashboard account, so its results appear in that user's "
        "dashboard (the account must already exist). Without it the scan has no owner and is "
        "visible to no one until `scripts/claim_legacy.py` assigns it",
    )
    scan.add_argument(
        "--allow-private",
        action="store_true",
        help="permit loopback/private addresses (for a local lab). Off by default so a scan "
        "cannot be steered at internal infrastructure",
    )
    scan.add_argument(
        "--no-subdomains",
        action="store_true",
        help="scan only the given host; skip certificate-transparency subdomain enumeration",
    )
    scan.add_argument(
        "--ports",
        help="comma-separated TCP ports to scan, replacing the default list",
    )
    scan.add_argument("--top", type=int, default=10, help="findings to print when done")
    scan.set_defaults(func=cmd_scan)

    enrich = sub.add_parser("enrich", help="refresh the global CVE/KEV/EPSS cache")
    enrich.add_argument("--refresh", action="store_true", help="accepted for symmetry; always refreshes")
    enrich.add_argument("--no-epss", action="store_true", help="skip EPSS (faster, KEV only)")
    enrich.set_defaults(func=cmd_enrich)

    report = sub.add_parser("report", help="show top-ranked findings")
    report.add_argument("--top", type=int, default=10)
    report.set_defaults(func=cmd_report)

    sub.add_parser("status", help="show cache and inventory counts").set_defaults(func=cmd_status)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _setup_logging(args.verbose)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
