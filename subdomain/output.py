import termcolor

from subdomain.state import ScanState
from subdomain.utils import tldSorting, printlogo


def savedata(state: ScanState, output_path: str) -> None:
    """Write sorted subdomains to *output_path*."""
    print(termcolor.colored("\nWriting all the subdomains to given file...\n", color='yellow', attrs=['bold']))
    with open(output_path, 'w+') as f:
        for item in tldSorting(state.final_set):
            f.write(item + '\n')
    print(termcolor.colored("\nWriting Done..\n", color='yellow', attrs=['bold']))


def savecloudresults(state: ScanState, cloud_output_path: str) -> None:
    """Write cloud service URLs to *cloud_output_path*."""
    with open(cloud_output_path, 'w+') as f:
        for item in state.cloud_url_set:
            f.write(item + '\n')


def savesecretsresults(state: ScanState, secret_output_path: str) -> None:
    """Write discovered secrets to *secret_output_path*."""
    with open(secret_output_path, 'w+') as f:
        for location, secret_list in state.secret_dict.items():
            for secret in secret_list:
                f.write(secret + ' | ' + location + '\n')


def save_github_secrets(state: ScanState, github_secrets_path: str) -> None:
    """Write GitHub-sourced secrets to *github_secrets_path*."""
    with open(github_secrets_path, 'w+') as f:
        for secret in state.github_secrets:
            f.write(secret + '\n')


def print_results(state: ScanState) -> None:
    """Print scan results to stdout."""
    print(termcolor.colored('_' * 60, color='white', attrs=['bold']))

    if state.final_set:
        print(termcolor.colored("\nGot some subdomains...", color='yellow', attrs=['bold']))
        print(termcolor.colored('Total Subdomains: ' + str(len(state.final_set)), color='red', attrs=['bold']))
        for item in tldSorting(state.final_set):
            print(termcolor.colored(item, color='green', attrs=['bold']))

    if state.cloud_url_set:
        print(termcolor.colored('_' * 60, color='white', attrs=['bold']))
        print(termcolor.colored("\nSome cloud services urls are found...", color='yellow', attrs=['bold']))
        print(termcolor.colored('Total Cloud URLs: ' + str(len(state.cloud_url_set)), color='red', attrs=['bold']))
        for item in state.cloud_url_set:
            print(termcolor.colored(item, color='green', attrs=['bold']))

    if state.secret_dict:
        print(termcolor.colored('_' * 60, color='white', attrs=['bold']))
        print(termcolor.colored("\nFound some secrets(might be false positive)...", color='yellow', attrs=['bold']))
        total = sum(len(lst) for lst in state.secret_dict.values())
        print(termcolor.colored('Total Possible Secrets: ' + str(total), color='red', attrs=['bold']))
        for file_url, secrets in state.secret_dict.items():
            for secret in set(secrets):
                print(termcolor.colored(secret, color='green', attrs=['bold']),
                      termcolor.colored("| " + file_url, color='yellow', attrs=['bold']))
