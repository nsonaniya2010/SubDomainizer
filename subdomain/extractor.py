import re
from multiprocessing.dummy import Pool as ThreadPool
from itertools import repeat

import termcolor

from subdomain.state import ScanState
from subdomain.utils import entropy
from subdomain.patterns.secrets import is_generic_placeholder


def compile_ip_regex():
    """Return a compiled regex that matches IPv4 addresses."""
    # Each octet group: (2[0-5][0-5].)|(2[0-4][0-9].)|(0?0?[0-9].)
    octet = r'(?:(?:2[0-5][0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])\.)'
    last  = r'(?:2[0-5][0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])'
    return re.compile(r'(' + octet + r'{3}' + last + r')')


def compile_domain_regex(domain: str):
    """Return a compiled regex that matches subdomains of *domain*."""
    return re.compile(
        r'([a-zA-Z0-9][a-zA-Z0-9\-.]*[a-zA-Z0-9]\.' + re.escape(domain) + r')',
        re.IGNORECASE,
    )


def compile_custom_domains_regex(domains: str):
    """Return a compiled regex that matches subdomains of any comma-separated domain."""
    prefix = r'[a-zA-Z0-9][0-9a-zA-Z\-.]*\.'
    parts = [prefix + d.strip() for d in domains.split(',')]
    return re.compile(r'(' + '|'.join(parts) + r')', re.IGNORECASE)


def get_info_from_data(
    item_url: str,
    item_values,
    state: ScanState,
    cloudlist: list,
    generic_pat,
    specific_patterns: list,
    domain_regex,
    ip_regex,
    custom_domains_regex,
    github_out: str = None,
) -> None:
    """Analyse one content source for cloud URLs, secrets, and subdomains.

    All results are written to *state* instead of module-level globals.
    """
    text = str(item_values).replace('\n', ' ')

    for pat in cloudlist:
        for item in pat.findall(text):
            state.cloud_url_set.add(item)

    for match in generic_pat.finditer(text):
        val = match.group(2)
        # Skip when the value is simply a mirror of the key
        # e.g. APP_API_KEY_CREATED="APP_API_KEY_CREATED"
        full = match.group(1)
        key_part = full[: len(full) - len(val)]
        key_norm = re.sub(r'[^a-z0-9]', '', key_part.lower())
        val_norm = re.sub(r'[^a-z0-9]', '', val.lower())
        if key_norm and val_norm and key_norm == val_norm:
            continue
        if entropy(val) > 3 and not is_generic_placeholder(val):
            entry = str(match.group())
            with state._lock:
                state.secret_dict[item_url].append(entry)
                if github_out and item_url.startswith("https://github.com"):
                    state.github_secrets.add(entry)

    for name, pat in specific_patterns:
        for match in pat.findall(text):
            entry = f'[{name}] {match}'
            with state._lock:
                state.secret_dict[item_url].append(entry)
                if github_out and item_url.startswith("https://github.com"):
                    state.github_secrets.add(entry)

    if domain_regex:
        for subdomain in domain_regex.findall(text):
            state.final_set.add(subdomain.lower())

    if custom_domains_regex:
        for subdomain in custom_domains_regex.findall(text):
            state.final_set.add(subdomain)


def getRecursiveFolderData(rootfolder: str):
    """Return (dict[path → content], total_count) for all readable files under *rootfolder*."""
    import glob
    import os

    folder_data = {}
    for filename in glob.iglob(rootfolder + '**/**', recursive=True):
        if os.path.isfile(filename):
            with open(filename, 'r') as fh:
                try:
                    folder_data[filename] = fh.read()
                except UnicodeDecodeError:
                    pass
    return folder_data, len(folder_data)


def subextractor(
    url: str,
    state: ScanState,
    cloudlist: list,
    generic_pat,
    specific_patterns: list,
    domain_regex,
    ip_regex,
    custom_domains_regex,
    github_out: str,
    heads: dict,
    ssl_verify: bool,
    pool_size: int,
    verbose: bool = True,
) -> None:
    """Fetch *url* and all linked JS, then scan everything for secrets/subdomains."""
    from subdomain.fetcher import JsExtract

    jsfile = JsExtract(state, heads, ssl_verify)
    jsfile.FetchAndExtract(url)

    jsthread = ThreadPool(pool_size)
    jsthread.map(jsfile.SaveExtJsContent, state.js_link_list)
    jsthread.close()
    jsthread.join()

    if verbose:
        print(termcolor.colored(
            "Finding secrets, cloud URLs, subdomains in all Javascript files...",
            color='yellow', attrs=['bold']))

    threads = ThreadPool(pool_size)
    threads.starmap(
        get_info_from_data,
        zip(
            state.new_final_dict.keys(),
            state.new_final_dict.values(),
            repeat(state),
            repeat(cloudlist),
            repeat(generic_pat),
            repeat(specific_patterns),
            repeat(domain_regex),
            repeat(ip_regex),
            repeat(custom_domains_regex),
            repeat(github_out),
        ),
    )
    threads.close()
    threads.join()

    if verbose:
        print(termcolor.colored("Searching completed...", color='blue', attrs=['bold']))
    state.final_list.clear()
