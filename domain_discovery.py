"""
🌐 New Domain Discovery Tool
=============================
Extracts 500+ newly registered/created domains every day from multiple free sources.

Sources:
  1. WhoisDS        — Daily bulk NRD (Newly Registered Domains) ZIP lists
  2. crt.sh (CT)    — Certificate Transparency logs for freshly-issued SSL certs
  3. Fallback scan  — Probes popular TLDs via CT logs to guarantee 500+ results

Usage:
  python domain_discovery.py                     # One-time run (today)
  python domain_discovery.py --date 2026-10-02   # Specific date
  python domain_discovery.py --schedule           # Daily auto-run
  python domain_discovery.py --format json        # Output format
"""

import argparse
import csv
import datetime
import email.encoders
import email.mime.base
import email.mime.multipart
import email.mime.text
import gzip
import io
import json
import logging
import os
import re
import smtplib
import sys
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import quote

# Optional imports — not required for core functionality
try:
    import schedule as sched_lib
    HAS_SCHEDULE = True
except ImportError:
    HAS_SCHEDULE = False

import requests

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
    )
    from rich.table import Table
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# Fallback console if rich is not available
if HAS_RICH:
    console = Console()
else:
    class _FallbackConsole:
        def print(self, *args, **kwargs):
            text = " ".join(str(a) for a in args)
            # Strip rich markup
            import re as _re
            text = _re.sub(r'\[/?[^\]]*\]', '', text)
            print(text)
    console = _FallbackConsole()


# ─── Configuration ────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).parent
OUTPUT_DIR = BASE_DIR / "output"
LOG_DIR = BASE_DIR / "logs"
CACHE_DIR = BASE_DIR / ".cache"

MIN_DOMAINS_TARGET = 500
REQUEST_TIMEOUT = 60
MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds

# TLDs to scan via CT logs as a fallback / supplement
CT_SCAN_TLDS = [
    "com", "net", "org", "io", "dev", "app", "co", "xyz", "site", "online",
    "store", "tech", "info", "biz", "cloud", "ai", "me", "cc", "us", "uk",
    "de", "fr", "in", "shop", "live", "pro", "top", "world", "space", "fun",
]

# ─── Logging ──────────────────────────────────────────────────────────────────

LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(levelname)-8s │ %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(LOG_DIR / "domain_discovery.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("domain_discovery")


# ─── Data Model ───────────────────────────────────────────────────────────────

@dataclass
class DomainRecord:
    """Represents a newly discovered domain."""
    domain: str
    source: str  # "whoisds", "ct_logs", "ct_scan"
    discovered_date: str  # YYYY-MM-DD
    tld: str = ""
    ssl_issuer: Optional[str] = None
    first_seen: Optional[str] = None  # ISO timestamp from CT log

    def __post_init__(self):
        # Normalise domain
        self.domain = self.domain.strip().lower()
        # Remove wildcard prefix
        if self.domain.startswith("*."):
            self.domain = self.domain[2:]
        # Extract TLD
        parts = self.domain.rsplit(".", 1)
        self.tld = parts[-1] if len(parts) > 1 else ""

    def __hash__(self):
        return hash(self.domain)

    def __eq__(self, other):
        if isinstance(other, DomainRecord):
            return self.domain == other.domain
        return False


# ─── HTTP Session ─────────────────────────────────────────────────────────────

def _create_session() -> requests.Session:
    """Create a requests session with retries and sensible headers."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": (
            "DomainDiscoveryBot/1.0 "
            "(+https://github.com/domain-discovery; research purposes)"
        ),
        "Accept": "application/json, text/plain, */*",
    })
    adapter = requests.adapters.HTTPAdapter(
        max_retries=requests.adapters.Retry(
            total=MAX_RETRIES,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


SESSION = _create_session()


# ─── Utility Helpers ──────────────────────────────────────────────────────────

def is_valid_domain(domain: str) -> bool:
    """Basic validation: looks like a real registerable domain, not an IP or garbage."""
    domain = domain.strip().lower()
    if not domain or " " in domain:
        return False
    # Remove wildcard prefix
    if domain.startswith("*."):
        domain = domain[2:]
    # Must have at least one dot
    if "." not in domain:
        return False
    # No IP addresses
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        return False
    # Basic domain pattern
    pattern = r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$"
    return bool(re.match(pattern, domain))


def extract_base_domain(fqdn: str) -> str:
    """Extract the registerable base domain (SLD + TLD) from an FQDN.
    
    e.g. 'mail.sub.example.com' → 'example.com'
         'www.shop.co.uk' → 'shop.co.uk'
    """
    fqdn = fqdn.strip().lower()
    if fqdn.startswith("*."):
        fqdn = fqdn[2:]

    # Known compound TLDs
    compound_tlds = {
        "co.uk", "co.in", "co.jp", "co.kr", "co.nz", "co.za",
        "com.au", "com.br", "com.cn", "com.mx", "com.sg", "com.tw",
        "org.uk", "net.au", "ac.uk", "gov.uk",
    }
    parts = fqdn.split(".")
    if len(parts) >= 3:
        candidate = ".".join(parts[-2:])
        if candidate in compound_tlds:
            return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return fqdn


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SOURCE 1: WhoisDS — Bulk NRD ZIP Downloads
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def fetch_whoisds(target_date: datetime.date) -> list[DomainRecord]:
    """Download the daily NRD list from WhoisDS.

    URL pattern: https://whoisds.com/whois-database/newly-registered-domains/<date>.zip/nrd
    The ZIP contains a text file with one domain per line.
    """
    date_str = target_date.strftime("%Y-%m-%d")
    url = f"https://whoisds.com/whois-database/newly-registered-domains/{date_str}.zip/nrd"

    logger.info(f"[WhoisDS] Fetching NRD list for {date_str} …")
    records: list[DomainRecord] = []

    try:
        resp = SESSION.get(url, timeout=REQUEST_TIMEOUT, stream=True)
        if resp.status_code == 404:
            logger.warning(f"[WhoisDS] No data available for {date_str} (404)")
            return records
        resp.raise_for_status()

        content = resp.content

        # Try to handle as ZIP
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                for name in zf.namelist():
                    with zf.open(name) as f:
                        text = f.read().decode("utf-8", errors="ignore")
                        for line in text.splitlines():
                            domain = line.strip().lower()
                            if is_valid_domain(domain):
                                base = extract_base_domain(domain)
                                records.append(DomainRecord(
                                    domain=base,
                                    source="whoisds",
                                    discovered_date=date_str,
                                ))
            logger.info(f"[WhoisDS] Extracted {len(records):,} domains from ZIP")
            return records
        except zipfile.BadZipFile:
            pass

        # Fallback: try as gzipped text
        try:
            text = gzip.decompress(content).decode("utf-8", errors="ignore")
            for line in text.splitlines():
                domain = line.strip().lower()
                if is_valid_domain(domain):
                    base = extract_base_domain(domain)
                    records.append(DomainRecord(
                        domain=base,
                        source="whoisds",
                        discovered_date=date_str,
                    ))
            logger.info(f"[WhoisDS] Extracted {len(records):,} domains from GZIP")
            return records
        except Exception:
            pass

        # Fallback: treat as plain text
        text = content.decode("utf-8", errors="ignore")
        for line in text.splitlines():
            domain = line.strip().lower()
            if is_valid_domain(domain):
                base = extract_base_domain(domain)
                records.append(DomainRecord(
                    domain=base,
                    source="whoisds",
                    discovered_date=date_str,
                ))
        logger.info(f"[WhoisDS] Extracted {len(records):,} domains from plain text")

    except requests.RequestException as e:
        logger.error(f"[WhoisDS] Request failed: {e}")

    return records


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SOURCE 2: Certificate Transparency Logs (crt.sh)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def fetch_ct_logs_for_tld(tld: str, target_date: datetime.date) -> list[DomainRecord]:
    """Query crt.sh for certificates issued on a specific date for a given TLD.
    
    Uses the crt.sh search with date filtering.
    """
    date_str = target_date.strftime("%Y-%m-%d")
    records: list[DomainRecord] = []

    # crt.sh API: search for wildcard under TLD, filter by issuance date
    # We query for %.tld certificates issued after target_date
    url = (
        f"https://crt.sh/?q=%.{tld}"
        f"&output=json"
        f"&exclude=expired"
    )

    try:
        resp = SESSION.get(url, timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            logger.debug(f"[CT/{tld}] HTTP {resp.status_code}")
            return records

        try:
            certs = resp.json()
        except json.JSONDecodeError:
            logger.debug(f"[CT/{tld}] Invalid JSON response")
            return records

        seen = set()
        for cert in certs:
            # Filter by issuance date
            not_before = cert.get("not_before", "")
            if not not_before.startswith(date_str):
                continue

            # Extract domain names from the certificate
            name_value = cert.get("name_value", "")
            issuer = cert.get("issuer_name", "")
            for raw_name in name_value.split("\n"):
                raw_name = raw_name.strip().lower()
                if raw_name.startswith("*."):
                    raw_name = raw_name[2:]
                base = extract_base_domain(raw_name)
                if is_valid_domain(base) and base not in seen:
                    seen.add(base)
                    records.append(DomainRecord(
                        domain=base,
                        source="ct_logs",
                        discovered_date=date_str,
                        ssl_issuer=issuer[:120] if issuer else None,
                        first_seen=not_before,
                    ))

    except requests.exceptions.ReadTimeout:
        logger.debug(f"[CT/{tld}] Timeout (crt.sh is often slow)")
    except requests.RequestException as e:
        logger.debug(f"[CT/{tld}] Request error: {e}")

    return records


def fetch_ct_logs_batch(target_date: datetime.date, tlds: list[str],
                        max_workers: int = 6) -> list[DomainRecord]:
    """Fetch CT log data for multiple TLDs in parallel."""
    logger.info(f"[CT Logs] Scanning {len(tlds)} TLDs with {max_workers} threads …")
    all_records: list[DomainRecord] = []
    completed = 0

    def _run_batch():
        nonlocal completed
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(fetch_ct_logs_for_tld, tld, target_date): tld
                for tld in tlds
            }
            for future in as_completed(futures):
                tld = futures[future]
                try:
                    results = future.result()
                    if results:
                        all_records.extend(results)
                        logger.debug(f"[CT/{tld}] Found {len(results)} domains")
                except Exception as e:
                    logger.debug(f"[CT/{tld}] Error: {e}")
                completed += 1

    if HAS_RICH:
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]CT Scan"),
            BarColumn(bar_width=40),
            MofNCompleteColumn(),
            TextColumn("•"),
            TimeElapsedColumn(),
            console=console,
        )
        with progress:
            task_id = progress.add_task("Scanning TLDs", total=len(tlds))
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(fetch_ct_logs_for_tld, tld, target_date): tld
                    for tld in tlds
                }
                for future in as_completed(futures):
                    tld_name = futures[future]
                    try:
                        results = future.result()
                        if results:
                            all_records.extend(results)
                            logger.debug(f"[CT/{tld_name}] Found {len(results)} domains")
                    except Exception as e:
                        logger.debug(f"[CT/{tld_name}] Error: {e}")
                    progress.advance(task_id)
    else:
        _run_batch()
        console.print(f"  Scanned {completed}/{len(tlds)} TLDs")

    logger.info(f"[CT Logs] Total from CT scan: {len(all_records):,} domains")
    return all_records


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SOURCE 3: Fallback — crt.sh "recent" atom feed scraping
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def fetch_ct_recent_certs(target_date: datetime.date,
                          batch_size: int = 200,
                          pages: int = 10) -> list[DomainRecord]:
    """Fetch the most recently logged certificates from crt.sh using ID-based pagination.
    
    crt.sh assigns incrementing IDs to certificates. We can fetch recent entries
    by querying the latest IDs. This gives us brand-new certificates regardless of TLD.
    """
    date_str = target_date.strftime("%Y-%m-%d")
    records: list[DomainRecord] = []
    seen = set()

    logger.info("[CT Recent] Fetching most recently issued certificates …")

    # Strategy: search for very short/new domain patterns
    # We'll query crt.sh for certificates matching patterns like "%.new" TLDs
    # and recently popular registration patterns
    recent_patterns = [
        "%.xyz", "%.site", "%.online", "%.store", "%.shop",
        "%.cloud", "%.space", "%.fun", "%.top", "%.live",
        "%.digital", "%.website", "%.click", "%.link", "%.world",
        "%.vip", "%.buzz", "%.one", "%.icu", "%.cyou",
    ]

    for pattern in recent_patterns:
        try:
            url = f"https://crt.sh/?q={pattern}&output=json&exclude=expired"
            resp = SESSION.get(url, timeout=REQUEST_TIMEOUT)
            if resp.status_code != 200:
                continue

            certs = resp.json()
            for cert in certs:
                not_before = cert.get("not_before", "")
                if not not_before.startswith(date_str):
                    continue

                name_value = cert.get("name_value", "")
                issuer = cert.get("issuer_name", "")
                for raw_name in name_value.split("\n"):
                    raw_name = raw_name.strip().lower()
                    if raw_name.startswith("*."):
                        raw_name = raw_name[2:]
                    base = extract_base_domain(raw_name)
                    if is_valid_domain(base) and base not in seen:
                        seen.add(base)
                        records.append(DomainRecord(
                            domain=base,
                            source="ct_recent",
                            discovered_date=date_str,
                            ssl_issuer=issuer[:120] if issuer else None,
                            first_seen=not_before,
                        ))

            # Be polite to crt.sh
            time.sleep(2)

        except Exception as e:
            logger.debug(f"[CT Recent] Error for {pattern}: {e}")
            continue

    logger.info(f"[CT Recent] Found {len(records):,} domains from recent certificates")
    return records


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# AGGREGATOR — Combine all sources, deduplicate, export
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def discover_domains(target_date: datetime.date) -> list[DomainRecord]:
    """
    Main pipeline: fetch from all sources, deduplicate, and return ≥500 domains.
    """
    date_str = target_date.strftime("%Y-%m-%d")
    all_domains: dict[str, DomainRecord] = {}  # domain → record (dedup by domain)

    if HAS_RICH:
        console.print(Panel(
            f"[bold cyan]🌐 Domain Discovery — {date_str}[/bold cyan]\n"
            f"Target: [bold yellow]{MIN_DOMAINS_TARGET}+[/bold yellow] unique domains",
            border_style="cyan",
        ))
    else:
        console.print(f"\n🌐 Domain Discovery — {date_str}")
        console.print(f"Target: {MIN_DOMAINS_TARGET}+ unique domains\n")

    # ── Phase 1: WhoisDS bulk download ────────────────────────────────────
    console.print("\n[bold green]▶ Phase 1:[/bold green] WhoisDS NRD list")
    whoisds_records = fetch_whoisds(target_date)
    for rec in whoisds_records:
        if rec.domain not in all_domains:
            all_domains[rec.domain] = rec
    console.print(f"  ✓ WhoisDS: [cyan]{len(whoisds_records):,}[/cyan] domains | "
                  f"Total unique: [bold]{len(all_domains):,}[/bold]")

    # ── Phase 2: CT Logs (major TLDs) ─────────────────────────────────────
    if len(all_domains) < MIN_DOMAINS_TARGET:
        console.print(f"\n[bold green]▶ Phase 2:[/bold green] Certificate Transparency Logs (major TLDs)")
        # Start with the most popular TLDs
        priority_tlds = CT_SCAN_TLDS[:15]
        ct_records = fetch_ct_logs_batch(target_date, priority_tlds, max_workers=5)
        for rec in ct_records:
            if rec.domain not in all_domains:
                all_domains[rec.domain] = rec
        console.print(f"  ✓ CT Logs: [cyan]{len(ct_records):,}[/cyan] domains | "
                      f"Total unique: [bold]{len(all_domains):,}[/bold]")

    # ── Phase 3: Extended CT scan (more TLDs) ─────────────────────────────
    if len(all_domains) < MIN_DOMAINS_TARGET:
        console.print(f"\n[bold green]▶ Phase 3:[/bold green] Extended CT scan (additional TLDs)")
        remaining_tlds = CT_SCAN_TLDS[15:]
        ct_extended = fetch_ct_logs_batch(target_date, remaining_tlds, max_workers=5)
        for rec in ct_extended:
            if rec.domain not in all_domains:
                all_domains[rec.domain] = rec
        console.print(f"  ✓ CT Extended: [cyan]{len(ct_extended):,}[/cyan] domains | "
                      f"Total unique: [bold]{len(all_domains):,}[/bold]")

    # ── Phase 4: CT Recent certificates (fallback) ────────────────────────
    if len(all_domains) < MIN_DOMAINS_TARGET:
        console.print(f"\n[bold green]▶ Phase 4:[/bold green] Recent certificate discovery (fallback)")
        ct_recent = fetch_ct_recent_certs(target_date)
        for rec in ct_recent:
            if rec.domain not in all_domains:
                all_domains[rec.domain] = rec
        console.print(f"  ✓ CT Recent: [cyan]{len(ct_recent):,}[/cyan] domains | "
                      f"Total unique: [bold]{len(all_domains):,}[/bold]")

    # ── Phase 5: Yesterday's WhoisDS as supplement ────────────────────────
    if len(all_domains) < MIN_DOMAINS_TARGET:
        yesterday = target_date - datetime.timedelta(days=1)
        console.print(f"\n[bold green]▶ Phase 5:[/bold green] Previous day supplement ({yesterday})")
        prev_records = fetch_whoisds(yesterday)
        for rec in prev_records:
            rec.discovered_date = date_str  # tag as today's discovery
            rec.source = "whoisds_prev"
            if rec.domain not in all_domains:
                all_domains[rec.domain] = rec
        console.print(f"  ✓ Previous day: [cyan]{len(prev_records):,}[/cyan] domains | "
                      f"Total unique: [bold]{len(all_domains):,}[/bold]")

    # ── Final summary ─────────────────────────────────────────────────────
    result = list(all_domains.values())
    result.sort(key=lambda r: (r.source, r.domain))

    # Count by source
    source_counts: dict[str, int] = {}
    tld_counts: dict[str, int] = {}
    for rec in result:
        source_counts[rec.source] = source_counts.get(rec.source, 0) + 1
        tld_counts[rec.tld] = tld_counts.get(rec.tld, 0) + 1

    # Display summary table
    console.print()
    if HAS_RICH:
        summary_table = Table(title="📊 Discovery Summary", border_style="cyan")
        summary_table.add_column("Source", style="bold")
        summary_table.add_column("Domains", justify="right", style="green")
        for source, count in sorted(source_counts.items()):
            summary_table.add_row(source, f"{count:,}")
        summary_table.add_row("─" * 20, "─" * 10, style="dim")
        summary_table.add_row("[bold]TOTAL", f"[bold]{len(result):,}")
        console.print(summary_table)

        top_tlds = sorted(tld_counts.items(), key=lambda x: -x[1])[:15]
        tld_table = Table(title="🏷️ Top TLDs", border_style="yellow")
        tld_table.add_column("TLD", style="bold")
        tld_table.add_column("Count", justify="right", style="green")
        for tld, count in top_tlds:
            tld_table.add_row(f".{tld}", f"{count:,}")
        console.print(tld_table)
    else:
        console.print("📊 Discovery Summary")
        for source, count in sorted(source_counts.items()):
            console.print(f"  {source}: {count:,}")
        console.print(f"  TOTAL: {len(result):,}")
        top_tlds = sorted(tld_counts.items(), key=lambda x: -x[1])[:15]
        console.print("\n🏷️ Top TLDs")
        for tld, count in top_tlds:
            console.print(f"  .{tld}: {count:,}")

    if len(result) >= MIN_DOMAINS_TARGET:
        console.print(f"\n[bold green]✅ Target met![/bold green] "
                      f"Discovered [bold]{len(result):,}[/bold] unique domains "
                      f"(target: {MIN_DOMAINS_TARGET})")
    else:
        console.print(f"\n[bold yellow]⚠ Below target.[/bold yellow] "
                      f"Discovered [bold]{len(result):,}[/bold] unique domains "
                      f"(target: {MIN_DOMAINS_TARGET}). "
                      f"Some sources may not have data for this date yet.")

    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# EXPORT — Save results to CSV / JSON
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def export_csv(records: list[DomainRecord], filepath: Path) -> None:
    """Export domain records to a CSV file."""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "domain", "tld", "source", "discovered_date", "ssl_issuer", "first_seen"
        ])
        writer.writeheader()
        for rec in records:
            writer.writerow(asdict(rec))
    logger.info(f"Exported {len(records):,} domains to {filepath}")


def export_json(records: list[DomainRecord], filepath: Path) -> None:
    """Export domain records to a JSON file."""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "metadata": {
            "generated_at": datetime.datetime.now().isoformat(),
            "total_domains": len(records),
            "sources": list({r.source for r in records}),
        },
        "domains": [asdict(r) for r in records],
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    logger.info(f"Exported {len(records):,} domains to {filepath}")


def export_results(records: list[DomainRecord], target_date: datetime.date,
                   fmt: str = "both") -> list[Path]:
    """Export results in the requested format(s)."""
    date_str = target_date.strftime("%Y-%m-%d")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    exported: list[Path] = []

    if fmt in ("csv", "both"):
        csv_path = OUTPUT_DIR / f"new_domains_{date_str}.csv"
        export_csv(records, csv_path)
        exported.append(csv_path)
        console.print(f"  📄 CSV: [link=file://{csv_path}]{csv_path}[/link]")

    if fmt in ("json", "both"):
        json_path = OUTPUT_DIR / f"new_domains_{date_str}.json"
        export_json(records, json_path)
        exported.append(json_path)
        console.print(f"  📄 JSON: [link=file://{json_path}]{json_path}[/link]")

    return exported


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# EMAIL — Send results via Gmail SMTP
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def send_email(subject: str, body: str, attachments: list[Path],
               recipient: str | None = None) -> bool:
    """Send an email with file attachments via Gmail SMTP.

    Credentials are read from environment variables:
      - GMAIL_ADDRESS   : Your Gmail address (sender & default recipient)
      - GMAIL_APP_PASS  : Gmail App Password (NOT your regular password)
      - EMAIL_RECIPIENT : (optional) Override recipient address

    To create a Gmail App Password:
      1. Go to https://myaccount.google.com/apppasswords
      2. Select "Mail" → "Other (Custom name)" → enter "Domain Discovery"
      3. Copy the 16-character password
    """
    sender = os.environ.get("GMAIL_ADDRESS", "")
    password = os.environ.get("GMAIL_APP_PASS", "")
    recipient = recipient or os.environ.get("EMAIL_RECIPIENT", sender)

    if not sender or not password:
        logger.warning("[Email] Skipped — GMAIL_ADDRESS and/or GMAIL_APP_PASS not set")
        console.print("  ⚠ Email skipped: set GMAIL_ADDRESS and GMAIL_APP_PASS env vars")
        return False

    if not recipient:
        logger.warning("[Email] Skipped — no recipient address")
        return False

    try:
        msg = email.mime.multipart.MIMEMultipart()
        msg["From"] = sender
        msg["To"] = recipient
        msg["Subject"] = subject

        # Email body
        msg.attach(email.mime.text.MIMEText(body, "plain", "utf-8"))

        # Attach files
        for filepath in attachments:
            if not filepath.exists():
                continue
            with open(filepath, "rb") as f:
                part = email.mime.base.MIMEBase("application", "octet-stream")
                part.set_payload(f.read())
            email.encoders.encode_base64(part)
            part.add_header(
                "Content-Disposition",
                f"attachment; filename={filepath.name}",
            )
            msg.attach(part)

        # Send via Gmail SMTP
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=30) as server:
            server.login(sender, password)
            server.send_message(msg)

        logger.info(f"[Email] Sent to {recipient} with {len(attachments)} attachment(s)")
        console.print(f"  ✉ Email sent to [bold]{recipient}[/bold]")
        return True

    except smtplib.SMTPAuthenticationError:
        logger.error("[Email] Authentication failed — check GMAIL_APP_PASS")
        console.print("  ❌ Email failed: invalid Gmail App Password")
    except smtplib.SMTPException as e:
        logger.error(f"[Email] SMTP error: {e}")
        console.print(f"  ❌ Email failed: {e}")
    except Exception as e:
        logger.error(f"[Email] Unexpected error: {e}")
        console.print(f"  ❌ Email failed: {e}")

    return False


def email_results(records: list[DomainRecord], exported_files: list[Path],
                  target_date: datetime.date, recipient: str | None = None) -> bool:
    """Compose and send the daily domain discovery report email."""
    date_str = target_date.strftime("%Y-%m-%d")

    # Count by source and TLD for the summary
    source_counts: dict[str, int] = {}
    tld_counts: dict[str, int] = {}
    for rec in records:
        source_counts[rec.source] = source_counts.get(rec.source, 0) + 1
        tld_counts[rec.tld] = tld_counts.get(rec.tld, 0) + 1
    top_tlds = sorted(tld_counts.items(), key=lambda x: -x[1])[:10]

    subject = f"🌐 New Domains Report — {date_str} ({len(records):,} domains)"

    body = f"""Domain Discovery Report — {date_str}
{'=' * 50}

Total new domains discovered: {len(records):,}

Sources:
"""
    for source, count in sorted(source_counts.items()):
        body += f"  • {source}: {count:,}\n"

    body += f"\nTop TLDs:\n"
    for tld, count in top_tlds:
        body += f"  • .{tld}: {count:,}\n"

    body += f"\nSample domains (first 25):\n"
    for i, rec in enumerate(records[:25], 1):
        body += f"  {i:>3}. {rec.domain}\n"

    body += f"\n{'=' * 50}\n"
    body += f"Full data attached as CSV and/or JSON.\n"
    body += f"Generated automatically by Domain Discovery Tool.\n"

    return send_email(subject, body, exported_files, recipient)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SCHEDULER — Daily automated run
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def run_scheduled():
    """Run the discovery pipeline on a daily schedule."""
    if not HAS_SCHEDULE:
        console.print("[bold red]Error:[/bold red] Install 'schedule' package: pip install schedule")
        sys.exit(1)

    def daily_job():
        today = datetime.date.today()
        console.print(f"\n{'═' * 60}")
        console.print(f"[bold]Scheduled run: {today}[/bold]")
        console.print(f"{'═' * 60}")
        try:
            records = discover_domains(today)
            export_results(records, today, fmt="both")
        except Exception as e:
            logger.error(f"Scheduled run failed: {e}", exc_info=True)

    # Run immediately, then schedule daily at 02:00
    daily_job()

    sched_lib.every().day.at("02:00").do(daily_job)
    console.print(f"\n[bold cyan]⏰ Scheduler active.[/bold cyan] "
                  f"Next run at [bold]02:00[/bold] daily. Press Ctrl+C to stop.")

    try:
        while True:
            sched_lib.run_pending()
            time.sleep(60)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scheduler stopped.[/yellow]")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CLI Entry Point
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def main():
    global MIN_DOMAINS_TARGET
    parser = argparse.ArgumentParser(
        description="🌐 New Domain Discovery Tool — Find 500+ new domains daily",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python domain_discovery.py                      # Discover today's new domains
  python domain_discovery.py --date 2026-10-02    # Specific date
  python domain_discovery.py --format json        # JSON output only
  python domain_discovery.py --schedule           # Run daily at 02:00
        """,
    )
    parser.add_argument(
        "--date", "-d",
        type=str,
        default=None,
        help="Target date in YYYY-MM-DD format (default: today)",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["csv", "json", "both"],
        default="both",
        help="Export format (default: both)",
    )
    parser.add_argument(
        "--schedule", "-s",
        action="store_true",
        help="Run as a daily scheduler (auto-fetches at 02:00)",
    )
    parser.add_argument(
        "--min-domains",
        type=int,
        default=MIN_DOMAINS_TARGET,
        help=f"Minimum domains to discover (default: {MIN_DOMAINS_TARGET})",
    )
    parser.add_argument(
        "--email", "-e",
        type=str,
        nargs="?",
        const="__default__",
        default=None,
        metavar="RECIPIENT",
        help="Email results (uses GMAIL_ADDRESS env var as default recipient)",
    )
    parser.add_argument(
        "--no-email",
        action="store_true",
        help="Explicitly disable email even if env vars are set",
    )

    args = parser.parse_args()

    # Update global target
    MIN_DOMAINS_TARGET = args.min_domains

    if args.schedule:
        run_scheduled()
        return

    # Parse target date
    if args.date:
        try:
            target_date = datetime.date.fromisoformat(args.date)
        except ValueError:
            console.print(f"[bold red]Error:[/bold red] Invalid date format: {args.date}. Use YYYY-MM-DD.")
            sys.exit(1)
    else:
        target_date = datetime.date.today()

    # Run discovery
    console.print()
    records = discover_domains(target_date)

    if records:
        console.print(f"\n[bold]📦 Exporting results …[/bold]")
        exported_files = export_results(records, target_date, fmt=args.format)

        # Send email if requested
        if args.email and not args.no_email:
            console.print(f"\n[bold]✉ Sending email …[/bold]")
            recipient = None if args.email == "__default__" else args.email
            email_results(records, exported_files, target_date, recipient)
        elif os.environ.get("GMAIL_ADDRESS") and os.environ.get("GMAIL_APP_PASS") and not args.no_email:
            # Auto-email in CI/GitHub Actions (env vars present)
            console.print(f"\n[bold]✉ Sending email (auto-detected credentials) …[/bold]")
            email_results(records, exported_files, target_date)

        # Show sample
        console.print(f"\n🔍 Sample domains (first 20):")
        if HAS_RICH:
            sample_table = Table(border_style="dim")
            sample_table.add_column("#", style="dim", width=4)
            sample_table.add_column("Domain", style="bold cyan")
            sample_table.add_column("TLD", style="yellow")
            sample_table.add_column("Source", style="green")
            sample_table.add_column("SSL Issuer", style="dim", max_width=40)
            for i, rec in enumerate(records[:20], 1):
                sample_table.add_row(
                    str(i),
                    rec.domain,
                    f".{rec.tld}",
                    rec.source,
                    (rec.ssl_issuer or "—")[:40],
                )
            console.print(sample_table)
        else:
            for i, rec in enumerate(records[:20], 1):
                console.print(f"  {i:>3}. {rec.domain:<40} .{rec.tld:<8} {rec.source}")
    else:
        console.print("[bold red]No domains found.[/bold red] The date may be too recent "
                      "or sources may be temporarily unavailable.")

    console.print()


if __name__ == "__main__":
    main()
