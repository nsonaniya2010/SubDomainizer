import termcolor

from subdomain.utils import tldSorting


def savedata(result, output_path: str) -> None:
    """Write sorted subdomains to *output_path*."""
    print(termcolor.colored("\nWriting all the subdomains to given file...\n", color='yellow', attrs=['bold']))
    with open(output_path, 'w+') as f:
        for item in tldSorting(result.subdomains):
            f.write(item + '\n')
    print(termcolor.colored("\nWriting Done..\n", color='yellow', attrs=['bold']))


def savecloudresults(result, cloud_output_path: str) -> None:
    """Write cloud service URLs to *cloud_output_path*."""
    with open(cloud_output_path, 'w+') as f:
        for item in result.cloud_urls:
            f.write(item + '\n')


def savesecretsresults(result, secret_output_path: str) -> None:
    """Write discovered secrets to *secret_output_path*."""
    with open(secret_output_path, 'w+') as f:
        for location, secret_list in result.secrets.items():
            for secret in secret_list:
                f.write(secret + ' | ' + location + '\n')


def save_github_secrets(result, github_secrets_path: str) -> None:
    """Write GitHub-sourced secrets to *github_secrets_path*."""
    with open(github_secrets_path, 'w+') as f:
        for secret in result.github_secrets:
            f.write(secret + '\n')


def print_results(result) -> None:
    """Print scan results to stdout."""
    print(termcolor.colored('_' * 60, color='white', attrs=['bold']))

    if result.subdomains:
        print(termcolor.colored("\nGot some subdomains...", color='yellow', attrs=['bold']))
        print(termcolor.colored('Total Subdomains: ' + str(len(result.subdomains)), color='red', attrs=['bold']))
        for item in tldSorting(result.subdomains):
            print(termcolor.colored(item, color='green', attrs=['bold']))

    if result.cloud_urls:
        print(termcolor.colored('_' * 60, color='white', attrs=['bold']))
        print(termcolor.colored("\nSome cloud services urls are found...", color='yellow', attrs=['bold']))
        print(termcolor.colored('Total Cloud URLs: ' + str(len(result.cloud_urls)), color='red', attrs=['bold']))
        for item in result.cloud_urls:
            print(termcolor.colored(item, color='green', attrs=['bold']))

    if result.secrets:
        print(termcolor.colored('_' * 60, color='white', attrs=['bold']))
        print(termcolor.colored("\nFound some secrets(might be false positive)...", color='yellow', attrs=['bold']))
        total = sum(len(lst) for lst in result.secrets.values())
        print(termcolor.colored('Total Possible Secrets: ' + str(total), color='red', attrs=['bold']))
        for file_url, secrets in result.secrets.items():
            for secret in set(secrets):
                print(termcolor.colored(secret, color='green', attrs=['bold']),
                      termcolor.colored("| " + file_url, color='yellow', attrs=['bold']))

    if result.passive_dns:
        print(termcolor.colored('_' * 60, color='white', attrs=['bold']))
        print(termcolor.colored("\nPassive DNS breakdown...", color='yellow', attrs=['bold']))
        for source, subs in result.passive_dns.items():
            if subs:
                print(termcolor.colored(f"  [{source}] {len(subs)} subdomain(s):", color='blue', attrs=['bold']))
                for sub in subs:
                    print(termcolor.colored("    " + sub, color='green', attrs=['bold']))
