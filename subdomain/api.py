import json
import os
from dataclasses import dataclass, field
from itertools import repeat
from multiprocessing.dummy import Pool as ThreadPool
from urllib.parse import urlparse

from subdomain.extractor import (
    compile_ip_regex,
    compile_domain_regex,
    compile_custom_domains_regex,
    get_info_from_data,
    getRecursiveFolderData,
    subextractor,
)
from subdomain.github import getUrlsFromData, get_github_data
from subdomain.passive import passive_enum
from subdomain.patterns.cloud import compile_cloud_patterns
from subdomain.patterns.secrets import (
    compile_generic_secret_regex,
    compile_specific_secret_patterns,
)
from subdomain.state import ScanState
from subdomain.utils import getDomain


@dataclass
class ScanConfig:
    """Configuration for a Scanner instance.

    All fields have sensible defaults so ``Scanner()`` works with zero config.
    """
    cookie: str = ""
    ssl_verify: bool = True
    github_token: str = ""
    custom_domains: str = ""
    san_mode: str = ""
    max_workers: int = field(
        default_factory=lambda: min(32, (os.cpu_count() or 1) + 8)
    )
    passive: bool = True
    verbose: bool = True


@dataclass
class ScanResult:
    """Structured output returned by every Scanner scan method."""
    subdomains: list
    cloud_urls: list
    secrets: dict
    github_secrets: list
    passive_dns: dict

    def to_dict(self) -> dict:
        return {
            "subdomains": self.subdomains,
            "cloud_urls": self.cloud_urls,
            "secrets": self.secrets,
            "github_secrets": self.github_secrets,
            "passive_dns": self.passive_dns,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class Scanner:
    """High-level programmatic interface to SubDomainizer.

    Patterns are compiled once on construction; each scan method creates an
    isolated ScanState so multiple calls are independent.

    Usage::

        from subdomain import Scanner, ScanConfig

        result = Scanner().scan_url("https://example.com")
        print(result.to_json())

        # With options
        cfg = ScanConfig(github_token="ghp_...", passive=True, verbose=False)
        result = Scanner(cfg).scan_urls(["https://a.com", "https://b.com"])
    """

    _UA = "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/70.0"

    def __init__(self, config: ScanConfig = None):
        self.config = config or ScanConfig()
        self._cloud_patterns = compile_cloud_patterns()
        self._generic_pat = compile_generic_secret_regex()
        self._specific_patterns = compile_specific_secret_patterns()
        self._ip_regex = compile_ip_regex()
        self._custom_dom_regex = (
            compile_custom_domains_regex(self.config.custom_domains)
            if self.config.custom_domains
            else None
        )

    # ── Public scan methods ───────────────────────────────────────────────

    def scan_url(self, url: str) -> ScanResult:
        """Scan a single URL and return structured results."""
        return self.scan_urls([url])

    def scan_urls(self, urls: list) -> ScanResult:
        """Scan a list of URLs and return merged structured results."""
        state = ScanState()
        passive_dns: dict = {}
        heads = self._build_headers()
        domain_set: set = set()

        for target in urls:
            netloc = urlparse(target).netloc
            if netloc:
                state.final_set.add(netloc)
            domain = getDomain(target)
            if domain:
                domain_set.add(domain)
            dom_regex = compile_domain_regex(domain) if domain else None

            try:
                subextractor(
                    url=target,
                    state=state,
                    cloudlist=self._cloud_patterns,
                    generic_pat=self._generic_pat,
                    specific_patterns=self._specific_patterns,
                    domain_regex=dom_regex,
                    ip_regex=self._ip_regex,
                    custom_domains_regex=self._custom_dom_regex,
                    github_out="__capture__" if self.config.github_token else None,
                    heads=heads,
                    ssl_verify=self.config.ssl_verify,
                    pool_size=self.config.max_workers,
                    verbose=self.config.verbose,
                )
            except Exception:
                pass

            if len(urls) > 1:
                state.new_final_dict.clear()

        if self.config.github_token:
            self._run_github_scan(domain_set, state)

        if self.config.passive:
            self._run_passive(domain_set, state, passive_dns)

        return self._build_result(state, passive_dns)

    def scan_folder(self, folder: str) -> ScanResult:
        """Recursively scan a local folder and return structured results."""
        state = ScanState()

        if os.path.isfile(folder):
            folder_data = {}
            with open(folder, "rt", errors="ignore") as fh:
                folder_data[folder] = fh.read()
        else:
            folder_data, _ = getRecursiveFolderData(folder)

        normalized = {
            os.path.normpath(os.path.join(os.getcwd(), p)): d
            for p, d in folder_data.items()
        }

        pool = ThreadPool(self.config.max_workers)
        pool.starmap(
            get_info_from_data,
            zip(
                normalized.keys(),
                normalized.values(),
                repeat(state),
                repeat(self._cloud_patterns),
                repeat(self._generic_pat),
                repeat(self._specific_patterns),
                repeat(None),
                repeat(self._ip_regex),
                repeat(self._custom_dom_regex),
                repeat(None),
            ),
        )
        pool.close()
        pool.join()

        return self._build_result(state, {})

    # ── Internal helpers ──────────────────────────────────────────────────

    def _run_github_scan(self, domain_set: set, state: ScanState) -> None:
        for domain in domain_set:
            dom_regex = compile_domain_regex(domain)
            content_urls = getUrlsFromData(self.config.github_token, domain)

            git_pool = ThreadPool(self.config.max_workers)
            git_pool.starmap(
                get_github_data,
                [(u, state, self.config.github_token, self.config.ssl_verify)
                 for u in content_urls],
            )
            git_pool.close()
            git_pool.join()

            content_pool = ThreadPool(self.config.max_workers)
            content_pool.starmap(
                get_info_from_data,
                zip(
                    state.git_data.keys(),
                    state.git_data.values(),
                    repeat(state),
                    repeat(self._cloud_patterns),
                    repeat(self._generic_pat),
                    repeat(self._specific_patterns),
                    repeat(dom_regex),
                    repeat(self._ip_regex),
                    repeat(self._custom_dom_regex),
                    repeat("__capture__"),
                ),
            )
            content_pool.close()
            content_pool.join()

    def _run_passive(
        self, domain_set: set, state: ScanState, passive_dns: dict
    ) -> None:
        if not domain_set:
            return
        if self.config.verbose:
            import termcolor
            print(termcolor.colored(
                "\nRunning passive subdomain enumeration (crt.sh / Wayback / HudsonRock)...",
                color='yellow', attrs=['bold']))
        for domain in domain_set:
            results = passive_enum(domain, self.config.ssl_verify)
            total = sum(len(v) for v in results.values())
            for source, subs in results.items():
                passive_dns.setdefault(source, []).extend(sorted(subs))
                state.final_set.update(subs)
                if self.config.verbose and subs:
                    import termcolor
                    print(termcolor.colored(
                        f"  [{source}] {len(subs)} subdomain(s) for {domain}",
                        color='blue', attrs=['bold']))
            if self.config.verbose and total == 0:
                import termcolor
                print(termcolor.colored(
                    f"  No passive results for {domain}", color='blue', attrs=['bold']))

    def _build_headers(self) -> dict:
        headers = {"User-agent": self._UA}
        if self.config.cookie:
            headers["Cookie"] = self.config.cookie
        return headers

    def _build_result(self, state: ScanState, passive_dns: dict) -> ScanResult:
        return ScanResult(
            subdomains=sorted(state.final_set),
            cloud_urls=sorted(state.cloud_url_set),
            secrets={k: list(v) for k, v in state.secret_dict.items()},
            github_secrets=sorted(state.github_secrets),
            passive_dns={k: sorted(set(v)) for k, v in passive_dns.items()},
        )
