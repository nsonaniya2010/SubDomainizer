import queue
import socket
import ssl
import sys

import termcolor
import urllib3

from subdomain.api import Scanner, ScanConfig
from subdomain.utils import getDomain, tldExt, printlogo
from subdomain.output import (
    savedata, savecloudresults, savesecretsresults, save_github_secrets, print_results,
)


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
    p.add_argument('-j',   '--json',             help="Print results as JSON to stdout.", action='store_true')
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


def main():
    parser = build_parser()
    args = parser.parse_args()

    url         = args.url
    listfile    = args.listfile
    folder_name = args.folder

    if folder_name is None:
        argerror(url, listfile)
    if args.gitscan:
        gitArgError(args.gittoken, args.gitscan)

    config = ScanConfig(
        cookie=args.cookie or "",
        ssl_verify=not args.nossl,
        github_token=args.gittoken or "" if args.gitscan else "",
        custom_domains=args.domains or "",
        san_mode=args.subject_alt_name or "",
        passive=True,
        verbose=True,
    )

    scanner = Scanner(config)

    print(printlogo())

    if args.nossl:
        print(termcolor.colored("Disabled SSL Certificate Checking...", color='green', attrs=['bold']))
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        if folder_name and not url and not listfile:
            print(termcolor.colored("Getting data from folder recursively...", color='yellow', attrs=['bold']))
            result = scanner.scan_folder(folder_name)

        elif listfile:
            urls = list(_getUrlsFromFile(listfile))
            result = scanner.scan_urls(urls)

        else:
            result = scanner.scan_url(url)

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
        savedata(result, args.output)

    if args.cloudop:
        print(termcolor.colored("\nWriting all the cloud services URL's to given file...", color='yellow', attrs=['bold']))
        savecloudresults(result, args.cloudop)
        print(termcolor.colored("Written cloud services URL's in file: ", color='red', attrs=['bold']) + args.cloudop)

    if args.secretop:
        print(termcolor.colored("\nWriting all the secrets to given file...", color='yellow', attrs=['bold']))
        savesecretsresults(result, args.secretop)
        print(termcolor.colored("Written secrets in file: ", color='red', attrs=['bold']) + args.secretop)

    if args.json:
        print(result.to_json())
    else:
        print_results(result)

    if args.gitscan and result.github_secrets and args.gitsecretop:
        print(termcolor.colored('_' * 60, color='white', attrs=['bold']))
        print(termcolor.colored("\nWriting github secrets to the given file...", color='yellow', attrs=['bold']))
        try:
            save_github_secrets(result, args.gitsecretop)
            print(termcolor.colored("\nSaved", color='red', attrs=['bold']))
        except Exception:
            print(termcolor.colored("\nError in saving the github secrets file...", color='red', attrs=['bold']))

    # ── Subject Alternative Names ────────────────────────────────────────
    is_san = args.subject_alt_name
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
        subdomain_set = set(result.subdomains) | {tldExt(url)}

        for host in subdomain_set:
            tld = getDomain(host)
            q.put(host)
            while not q.empty():
                try:
                    hostname = q.get()
                    if is_san == "same":
                        if hostname not in printed and hostname not in subdomain_set and hostname.endswith(tld):
                            print(termcolor.colored(hostname, color='green', attrs=['bold']))
                            nothing_found = False
                            printed.add(hostname)
                    elif is_san == "all":
                        if hostname not in printed and hostname not in subdomain_set:
                            print(termcolor.colored(hostname, color='green', attrs=['bold']))
                            nothing_found = False
                            printed.add(hostname)

                    if hostname not in completed:
                        completed.add(hostname)
                        with socket.create_connection((hostname, 443)) as sock:
                            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                                for (_, v) in ssock.getpeercert()['subjectAltName']:
                                    clean = v.lstrip('*.')
                                    if v not in q.queue and clean not in subdomain_set:
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
