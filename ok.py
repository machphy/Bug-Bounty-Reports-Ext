#!/usr/bin/env python3
"""
report_extractor.py

Improved CLI tool to fetch resolved & disclosed HackerOne "hacktivity" reports
for a vulnerability keyword and export them to CSV.

Usage examples:
    python report_extractor.py -v "SQL Injection" -n 200
    python report_extractor.py -v "Cross Site Scripting" -o xss.csv -n 300 --delay 0.5 --verbose
"""

import argparse
import csv
import sys
import time
import math
import logging
from typing import List, Dict, Any, Optional

import requests

# ---- Configuration ----
GRAPHQL_URL = "https://hackerone.com/graphql"
DEFAULT_PAGE_SIZE = 100  # HackerOne typically returns up to 100
MAX_REPORTS_LIMIT = 3000
DEFAULT_TIMEOUT = 15  # seconds for HTTP requests
# -----------------------

# Simple color helper (optional)
class Color:
    RED = "\033[91m"
    ORANGE = "\033[38;5;208m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    BLUE = "\033[94m"
    RESET = "\033[0m"


def build_query():
    return """query HacktivitySearchQuery($queryString: String!, $from: Int, $size: Int, $sort: SortInput!) {
      me { id __typename }
      search(
        index: CompleteHacktivityReportIndex
        query_string: $queryString
        from: $from
        size: $size
        sort: $sort
      ) {
        __typename
        total_count
        nodes {
          __typename
          ... on HacktivityDocument {
            id
            _id
            severity_rating
            report {
              id
              _id
              title
              url
              disclosed_at
            }
          }
        }
      }
    }"""


def create_session(user_agent: Optional[str] = None) -> requests.Session:
    s = requests.Session()
    headers = {
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Content-Type": "application/json",
        "X-Product-Area": "hacktivity",
        "X-Product-Feature": "overview",
    }
    if user_agent:
        headers["User-Agent"] = user_agent
    else:
        headers["User-Agent"] = "report-extractor/1.0 (+https://github.com/)"

    s.headers.update(headers)
    return s


def fetch_page(session: requests.Session, query_string: str, offset: int, size: int, timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    payload = {
        "operationName": "HacktivitySearchQuery",
        "variables": {
            "queryString": query_string,
            "size": size,
            "from": offset,
            "sort": {
                "field": "latest_disclosable_activity_at",
                "direction": "DESC"
            },
            "product_area": "hacktivity",
            "product_feature": "overview"
        },
        "query": build_query()
    }

    resp = session.post(GRAPHQL_URL, json=payload, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    if "errors" in data:
        raise RuntimeError(f"GraphQL returned errors: {data['errors']}")
    return data


def safe_get_report_fields(node: Dict[str, Any]) -> Dict[str, str]:
    """Given a node, extract title, severity and url safely."""
    report = node.get("report") or {}
    title = report.get("title") or "<no title>"
    url = report.get("url") or ""
    severity = node.get("severity_rating") or ""
    return {"Title": title, "Severity": severity, "URL": url}


def exponential_backoff_retry(func, retries=4, initial_delay=1.0, backoff_factor=2.0, **kwargs):
    """Generic small retry wrapper with exponential backoff."""
    delay = initial_delay
    for attempt in range(1, retries + 1):
        try:
            return func(**kwargs)
        except (requests.exceptions.RequestException, RuntimeError) as e:
            if attempt == retries:
                raise
            sleep_for = delay
            logging.debug(f"Attempt {attempt}/{retries} failed: {e}. Retrying in {sleep_for:.1f}s...")
            time.sleep(sleep_for)
            delay *= backoff_factor


def fetch_reports(vuln_keyword: str, total: int, page_size: int = DEFAULT_PAGE_SIZE, delay: float = 0.2, verbose: bool = False) -> List[Dict[str, str]]:
    """
    Fetch up to `total` reports matching the query.
    Returns list of dicts with keys Title, Severity, URL.
    """
    if total <= 0:
        return []
    page_size = max(1, min(page_size, DEFAULT_PAGE_SIZE))
    session = create_session()
    query_string = f'cwe:("{vuln_keyword}") AND substate:("Resolved") AND disclosed:true'

    reports: List[Dict[str, str]] = []
    total_pages = math.ceil(total / page_size)

    for page_idx in range(total_pages):
        offset = page_idx * page_size
        size = min(page_size, total - offset)
        if verbose:
            logging.info(f"Fetching offset {offset} size {size} (page {page_idx + 1}/{total_pages})...")
        # wrapper to handle transient errors
        data = exponential_backoff_retry(
            func=fetch_page,
            retries=5,
            initial_delay=1.0,
            backoff_factor=2.0,
            session=session,
            query_string=query_string,
            offset=offset,
            size=size
        )

        # defensive parsing
        nodes = []
        try:
            nodes = data["data"]["search"].get("nodes", [])
        except Exception as e:
            logging.warning(f"Unexpected response format: {e}. Full response: {data}")
            break

        if not nodes:
            # no more nodes available
            if verbose:
                logging.info("No more nodes returned by API; stopping early.")
            break

        for node in nodes:
            try:
                reports.append(safe_get_report_fields(node))
            except Exception:
                # skip any malformed node but keep going
                logging.debug(f"Skipping malformed node: {node}")

        # small polite delay so we don't appear abusive
        if delay:
            time.sleep(delay)

        # stop early if fewer results returned than requested size
        if len(nodes) < size:
            if verbose:
                logging.info("API returned fewer results than requested for this page; reached end of results.")
            break

    return reports


def write_csv(path: str, rows: List[Dict[str, str]]):
    fieldnames = ["Title", "Severity", "URL"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)


def parse_args():
    p = argparse.ArgumentParser(
        description="Bug Bounty Reports Extractor - Fetch resolved & disclosed HackerOne reports by vulnerability and export to CSV."
    )
    p.add_argument("-v", "--vulnerability", nargs="+", required=True, help="Vulnerability name (CWE keyword or phrase). Example: -v \"SQL Injection\"")
    p.add_argument("-o", "--output", help="Output CSV file name (default: <vuln>.csv)")
    p.add_argument("-n", "--number", type=int, default=100, help="Number of reports to fetch (default 100, max 3000)")
    p.add_argument("--page-size", type=int, default=DEFAULT_PAGE_SIZE, help=f"Internal page size per request (default {DEFAULT_PAGE_SIZE}, max {DEFAULT_PAGE_SIZE})")
    p.add_argument("--delay", type=float, default=0.2, help="Delay in seconds between requests to be polite (default 0.2s)")
    p.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    return p.parse_args()


def main():
    args = parse_args()
    if args.verbose:
        logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING, format="[%(levelname)s] %(message)s")

    vuln_keyword = " ".join(args.vulnerability).strip()
    num = args.number
    if num <= 0:
        logging.error("Number of reports must be > 0")
        sys.exit(1)
    if num > MAX_REPORTS_LIMIT:
        logging.error(f"Number of reports must be <= {MAX_REPORTS_LIMIT}")
        sys.exit(1)

    output_file = args.output if args.output else f"{vuln_keyword.replace(' ', '_')}.csv"

    try:
        print(f"{Color.BLUE}[+] Searching HackerOne for: '{vuln_keyword}' (max {num} reports){Color.RESET}")
        reports = fetch_reports(vuln_keyword, total=num, page_size=args.page_size, delay=args.delay, verbose=args.verbose)

        if not reports:
            print(f"{Color.YELLOW}[-] No reports found for '{vuln_keyword}'.{Color.RESET}")
            return

        write_csv(output_file, reports)
        print(f"{Color.GREEN}[+] Saved {len(reports)} reports to {output_file}{Color.RESET}")

        # if user didn't specify custom output and terminal is interactive, print a compact summary
        if not args.output:
            print("\nSample (first 10):\n")
            for r in reports[:10]:
                sev = r["Severity"] or "No rating"
                color = Color.GREEN if sev.lower() == "low" else (Color.ORANGE if sev.lower() == "high" else Color.RED if sev.lower() == "critical" else Color.BLUE)
                print(f"{color}[#] {r['Title']}{Color.RESET}")
                print(f"    Severity: {sev}")
                print(f"    URL: {r['URL']}\n")

    except requests.exceptions.HTTPError as he:
        logging.error(f"HTTP error while contacting HackerOne: {he}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
