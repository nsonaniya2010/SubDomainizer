"""Passive subdomain enumeration from unauthenticated public APIs."""
import re
from datetime import datetime, timedelta
from urllib.parse import urlparse

import requests


def _extract_subdomains_from_urls(urls, base_domain: str) -> set:
    """Extract hostnames that are subdomains of base_domain from a list of URL strings."""
    subs = set()
    pattern = re.compile(
        r'([a-zA-Z0-9][a-zA-Z0-9\-.]*\.' + re.escape(base_domain) + r')\b',
        re.IGNORECASE,
    )
    for url in urls:
        for match in pattern.findall(str(url)):
            subs.add(match.lower())
    return subs


def _walk_json_for_strings(obj) -> list:
    """Recursively collect all string leaf values from any JSON structure."""
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        out = []
        for v in obj.values():
            out.extend(_walk_json_for_strings(v))
        return out
    if isinstance(obj, list):
        out = []
        for item in obj:
            out.extend(_walk_json_for_strings(item))
        return out
    return []


def fetch_hudsonrock(domain: str, ssl_verify: bool = True, timeout: int = 20) -> set:
    """Fetch compromised-credential URLs for *domain* from Hudson Rock Cavalier API.

    Endpoint: https://cavalier.hudsonrock.com/api/json/v2/osint-tools/urls-by-domain
    Unauthenticated. Returns URLs from stealer logs — subdomains are extracted
    from those URLs.
    """
    url = (
        "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/urls-by-domain"
        f"?domain={domain}"
    )
    try:
        resp = requests.get(url, timeout=timeout, verify=ssl_verify,
                            headers={"User-agent": "Mozilla/5.0"})
        resp.raise_for_status()
        data = resp.json()
        strings = _walk_json_for_strings(data)
        return _extract_subdomains_from_urls(strings, domain)
    except Exception:
        return set()


def fetch_crtsh(domain: str, ssl_verify: bool = True, timeout: int = 90) -> set:
    """Fetch subdomains from crt.sh certificate transparency logs.

    Endpoint: https://crt.sh/?q=%.DOMAIN&output=json
    Deduplicated via the built-in `deduplicate=Y` parameter to reduce payload size.
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json&deduplicate=Y"
    subs = set()
    try:
        resp = requests.get(url, timeout=timeout, verify=ssl_verify,
                            headers={
                                "User-agent": "Mozilla/5.0",
                                "Accept": "application/json",
                            })
        resp.raise_for_status()
        for entry in resp.json():
            for field in ('name_value', 'common_name'):
                for name in entry.get(field, '').split('\n'):
                    name = name.strip().lstrip('*.')
                    if name and name.endswith(domain):
                        subs.add(name.lower())
    except Exception:
        pass
    return subs


def fetch_wayback(domain: str, ssl_verify: bool = True, timeout: int = 180) -> set:
    """Fetch subdomains from Wayback Machine CDX API.

    Endpoint: https://web.archive.org/cdx/search/cdx?url=DOMAIN&matchType=domain
    Uses matchType=domain (bare domain, not wildcard) — the CDX-correct form that
    returns all archived URLs under the domain tree, sorted by CDX key. Results are
    capped at 5000 to bound response size; restricted to the last 2 years.
    """
    from_date = (datetime.now() - timedelta(days=730)).strftime('%Y%m%d')
    url = (
        "https://web.archive.org/cdx/search/cdx"
        f"?url={domain}&matchType=domain&fl=original&collapse=urlkey&from={from_date}&limit=5000"
    )
    subs = set()
    try:
        resp = requests.get(url, timeout=timeout, verify=ssl_verify,
                            headers={"User-agent": "Mozilla/5.0"})
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                host = (urlparse(line).hostname or '').lstrip('*.')
                if host and host.endswith(domain):
                    subs.add(host.lower())
            except Exception:
                pass
    except Exception:
        pass
    return subs


def passive_enum(domain: str, ssl_verify: bool = True) -> dict:
    """Run all passive enumeration sources concurrently.

    Returns {source_name: set_of_subdomains}.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    sources = {
        'crt.sh':          lambda: fetch_crtsh(domain, ssl_verify),
        'Wayback Machine': lambda: fetch_wayback(domain, ssl_verify),
        'HudsonRock':      lambda: fetch_hudsonrock(domain, ssl_verify),
    }
    results = {name: set() for name in sources}
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {pool.submit(fn): name for name, fn in sources.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception:
                pass
    return results
