import os
import queue
import socket
import ssl
import sys
from itertools import repeat
from multiprocessing.dummy import Pool as ThreadPool
from urllib.parse import urlparse

import requests
import termcolor
import urllib3

from subdomain.state import ScanState
from subdomain.utils import getDomain, tldExt, tldSorting, printlogo
from subdomain.patterns.secrets import compile_generic_secret_regex, compile_specific_secret_patterns
from subdomain.patterns.cloud import compile_cloud_patterns
from subdomain.extractor import (
    compile_ip_regex, compile_domain_regex, compile_custom_domains_regex,
    get_info_from_data, getRecursiveFolderData, subextractor,
)
from subdomain.github import getUrlsFromData, get_github_data
from subdomain.output import (
    savedata, savecloudresults, savesecretsresults, save_github_secrets, print_results,
)
from subdomain.passive import passive_enum

_THREAD_POOL_SIZE = min(32, (os.cpu_count() or 1) + 8)


def build_parser():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('-c',   '--cookie',          help="Cookie header value for requests.")
    p.add_argument('-cop', '--cloudop',          help="File to save cloud service URLs.")
    p.add_argument('-sop', '--secretop',         help="File to save secrets found.")
    p.add_argument('-gop', '--gitsecretop',      help="File to save secrets found on GitHub.")
    p.add_argument('-d',   '--domains',          help="Comma-separated domains to extract subdomains from.")
    p.add_argument('-f',   '--folder',           help="Folder to scan recursively.")
    p.add_argument('-g',   '--gitscan',          help="Scan GitHub for subdomains.", action='store_true')
    p.add_argument('-gt',  '--gittoken',         help="GitHub API auth token.")
    p.add_argument('-k',   '--nossl',            help="Disable SSL certificate verification.", action='store_true')
    p.add_argument('-l',   '--listfile',         help="File containing URLs to scan (one per line).")
    p.add_argument('-o',   '--output',           help="File to save discovered subdomains.")
    p.add_argument('-san', '--subject_alt_name', help="Get SANs from TLS certs: 'all' or 'same'.")
    p.add_argument('-u',   '--url',              help="URL to scan.")
    return p


def argerror(url, listfile):
    if (url is None and listfile is None) or (url is not None and listfile is not None):
        print("Atmost one of -u/--url or -l/--listfile or -f/--folder argument is required. Exiting...")
        sys.exit(1)


def gitArgError(git_token, is_git):
    if (git_token is None and is_git) or (git_token is not None and not is_git):
        print("Either both '-g' and '-gt' arguments are required or none required. Exiting...")
        sys.exit(1)


def _getUrlsFromFile(listfile_path: str) -> set:
    with open(listfile_path, 'rt') as f:
        lines = f.readlines()
    return {x.strip() for x in lines if x.strip()}


def _run_passive_enum(domain_set: set, state: ScanState, ssl_verify: bool) -> None:
    """Query passive enumeration sources for every domain in *domain_set*."""
    if not domain_set:
        return
    print(termcolor.colored(
        "\nRunning passive subdomain enumeration (crt.sh / Wayback / HudsonRock)...",
        color='yellow', attrs=['bold']))
    for domain in domain_set:
        results = passive_enum(domain, ssl_verify)
        total = sum(len(v) for v in results.values())
        for source, subs in results.items():
            if subs:
                print(termcolor.colored(
                    f"  [{source}] {len(subs)} subdomain(s) for {domain}",
                    color='blue', attrs=['bold']))
                state.final_set.update(subs)
        if total == 0:
            print(termcolor.colored(
                f"  No passive results for {domain}", color='blue', attrs=['bold']))


def main():
    parser = build_parser()
    args = parser.parse_args()

    url         = args.url
    listfile    = args.listfile
    cloudop     = args.cloudop
    secretop    = args.secretop
    git_token   = args.gittoken
    is_git      = args.gitscan
    is_ssl      = args.nossl          # True = skip SSL verification
    folder_name = args.folder
    is_san      = args.subject_alt_name
    github_out  = args.gitsecretop

    heads = {"User-agent": "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/70.0"}
    if args.cookie:
        heads["Cookie"] = args.cookie

    ssl_verify = not is_ssl

    state = ScanState()

    # Precompile patterns once
    cloud_patterns      = compile_cloud_patterns()
    generic_pat         = compile_generic_secret_regex()
    specific_patterns   = compile_specific_secret_patterns()
    ip_regex            = compile_ip_regex()
    custom_dom_regex    = compile_custom_domains_regex(args.domains) if args.domains else None

    try:
        print(printlogo())

        if is_ssl:
            print(termcolor.colored("Disabled SSL Certificate Checking...", color='green', attrs=['bold']))
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        domain_set: set = set()

        # ── Folder scan ─────────────────────────────────────────────────
        if folder_name and not url and not listfile:
            print(termcolor.colored("Getting data from folder recursively...", color='yellow', attrs=['bold']))

            if not os.path.isfile(folder_name):
                folder_data, total = getRecursiveFolderData(folder_name)
            else:
                folder_data = {}
                with open(folder_name, 'rt', errors='ignore') as fh:
                    try:
                        folder_data[folder_name] = fh.read()
                    except UnicodeDecodeError:
                        pass
                total = 1

            print(termcolor.colored("\nTotal files to scan: " + str(total) + '\n', color='red', attrs=['bold']))
            print(termcolor.colored("Finding secrets in files, Please wait...", color='blue', attrs=['bold']))

            normalized = {
                os.path.normpath(os.path.join(os.getcwd(), p)): d
                for p, d in folder_data.items()
            }
            pool = ThreadPool(_THREAD_POOL_SIZE)
            pool.starmap(get_info_from_data, zip(
                normalized.keys(), normalized.values(),
                repeat(state), repeat(cloud_patterns), repeat(generic_pat),
                repeat(specific_patterns), repeat(None), repeat(ip_regex),
                repeat(custom_dom_regex), repeat(github_out),
            ))
            pool.close()
            pool.join()

        # ── URL / listfile scan ─────────────────────────────────────────
        else:
            argerror(url, listfile)
            if is_git:
                gitArgError(git_token, is_git)

            urls = _getUrlsFromFile(listfile) if listfile else [url]

            for target in urls:
                state.final_set.add(urlparse(target).netloc)
                domain = getDomain(target)
                domain_set.add(domain)
                dom_regex = compile_domain_regex(domain)

                if listfile:
                    print(termcolor.colored("Extracting data from internal and external js for url:",
                                            color='blue', attrs=['bold']))
                    print(termcolor.colored(target, color='red', attrs=['bold']))

                try:
                    try:
                        subextractor(
                            url=target, state=state,
                            cloudlist=cloud_patterns, generic_pat=generic_pat,
                            specific_patterns=specific_patterns, domain_regex=dom_regex,
                            ip_regex=ip_regex, custom_domains_regex=custom_dom_regex,
                            github_out=github_out, heads=heads, ssl_verify=ssl_verify,
                            pool_size=_THREAD_POOL_SIZE,
                        )
                    except requests.exceptions.ConnectionError:
                        print(termcolor.colored(
                            'An error occured while fetching URL, one or more of following are possibilities:'
                            '\n1. Might be server is down.\n2. SSL certificate issue.\n3. Domain does not exist.'
                            '\nPlease check properly or try \'-k\' option.',
                            color='yellow', attrs=['bold']))
                        if not listfile:
                            sys.exit(1)
                except requests.exceptions.InvalidSchema:
                    print("Invalid Schema Provided!")
                    if not listfile:
                        sys.exit(1)

                if listfile:
                    state.new_final_dict.clear()

            # ── GitHub scan ─────────────────────────────────────────────
            if git_token and is_git:
                for item in domain_set:
                    dom_regex = compile_domain_regex(item)
                    print(termcolor.colored(
                        'Finding Subdomains and secrets from Github..Please wait...',
                        color='yellow', attrs=['bold']))
                    print(termcolor.colored(
                        'Searching in github for : ' + termcolor.colored(item, color='green', attrs=['bold']),
                        color='blue', attrs=['bold']))

                    content_urls = getUrlsFromData(git_token, item)

                    git_pool = ThreadPool(_THREAD_POOL_SIZE)
                    git_pool.starmap(get_github_data, [
                        (u, state, git_token, ssl_verify) for u in content_urls
                    ])
                    git_pool.close()
                    git_pool.join()

                    content_pool = ThreadPool(_THREAD_POOL_SIZE)
                    content_pool.starmap(get_info_from_data, zip(
                        state.git_data.keys(), state.git_data.values(),
                        repeat(state), repeat(cloud_patterns), repeat(generic_pat),
                        repeat(specific_patterns), repeat(dom_regex), repeat(ip_regex),
                        repeat(custom_dom_regex), repeat(github_out),
                    ))
                    content_pool.close()
                    content_pool.join()
                    print(termcolor.colored('Completed finding from github...', color='blue', attrs=['bold']))

            # ── Passive subdomain enumeration ────────────────────────────
            _run_passive_enum(domain_set, state, ssl_verify)

    except KeyboardInterrupt:
        print(termcolor.colored("\nKeyboard Interrupt. Exiting...\n", color='red', attrs=['bold']))
        sys.exit(1)
    except FileNotFoundError:
        print(termcolor.colored("\nFile Not found, Please check filename. Exiting...\n", color='yellow', attrs=['bold']))
        sys.exit(1)

    # ── Output ──────────────────────────────────────────────────────────
    print(termcolor.colored("Got all the important, printing and/or saving...\n", color='blue', attrs=['bold']))
    print(termcolor.colored('_' * 22 + 'Start of Results' + '_' * 22, color='white', attrs=['bold']))

    if args.output:
        savedata(state, args.output)

    if cloudop:
        print(termcolor.colored("\nWriting all the cloud services URL's to given file...", color='yellow', attrs=['bold']))
        savecloudresults(state, cloudop)
        print(termcolor.colored("Written cloud services URL's in file: ", color='red', attrs=['bold']) + cloudop)

    if secretop:
        print(termcolor.colored("\nWriting all the secrets to given file...", color='yellow', attrs=['bold']))
        savesecretsresults(state, secretop)
        print(termcolor.colored("Written secrets in file: ", color='red', attrs=['bold']) + secretop)

    print_results(state)

    if is_git and state.github_secrets:
        print(termcolor.colored('_' * 60, color='white', attrs=['bold']))
        print(termcolor.colored("\nWriting github secrets to the given file...", color='yellow', attrs=['bold']))
        try:
            save_github_secrets(state, github_out)
            print(termcolor.colored("\nSaved", color='red', attrs=['bold']))
        except Exception:
            print(termcolor.colored("\nError in saving the github secrets file...", color='red', attrs=['bold']))

    # ── Subject Alternative Names ────────────────────────────────────────
    if is_san in ("same", "all") and url and not folder_name:
        print(termcolor.colored('_' * 60, color='white', attrs=['bold']))
        print(termcolor.colored(
            "\nFinding additional subdomains using Subject Alternative Names(SANs)...\n",
            color='yellow', attrs=['bold']))

        nothing_found = True
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        socket.setdefaulttimeout(5)

        q = queue.Queue()
        printed: set = set()
        completed: set = set()
        state.final_set.add(tldExt(url))

        for host in state.final_set:
            tld = getDomain(host)
            q.put(host)
            while not q.empty():
                try:
                    hostname = q.get()
                    if is_san == "same":
                        if hostname not in printed and hostname not in state.final_set and hostname.endswith(tld):
                            print(termcolor.colored(hostname, color='green', attrs=['bold']))
                            nothing_found = False
                            printed.add(hostname)
                    elif is_san == "all":
                        if hostname not in printed and hostname not in state.final_set:
                            print(termcolor.colored(hostname, color='green', attrs=['bold']))
                            nothing_found = False
                            printed.add(hostname)

                    if hostname not in completed:
                        completed.add(hostname)
                        with socket.create_connection((hostname, 443)) as sock:
                            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                                for (_, v) in ssock.getpeercert()['subjectAltName']:
                                    clean = v.lstrip('*.')
                                    if v not in q.queue and clean not in state.final_set:
                                        q.put(clean)
                except (socket.gaierror, socket.timeout, ssl.SSLCertVerificationError,
                        ConnectionRefusedError, ssl.SSLError, OSError):
                    pass
                except KeyboardInterrupt:
                    print(termcolor.colored("\nKeyboard Interrupt. Exiting...\n", color='red', attrs=['bold']))
                    sys.exit(1)

        if nothing_found:
            print(termcolor.colored("No SANs found.", color='green', attrs=['bold']))

    print(termcolor.colored('\n' + '_' * 23 + 'End of Results' + '_' * 23 + '\n', color='white', attrs=['bold']))
