import base64
import json
from urllib.parse import unquote

import requests

from subdomain.state import ScanState


def getUrlsFromData(git_token: str, domain: str) -> set:
    """Return GitHub content API URLs for files that mention *domain*."""
    headers = {"Authorization": "token " + git_token}
    urls: set = set()
    for query in [
        f'https://api.github.com/search/code?q="{domain}"&per_page=100&sort=indexed',
        f'https://api.github.com/search/code?q="{domain}"&per_page=100',
    ]:
        try:
            data = json.loads(
                requests.get(query, verify=False, headers=headers, timeout=(20, 20))
                .content.decode('utf-8')
            )
            for item in data.get('items', []):
                if 'url' in item:
                    urls.add(item['url'])
        except Exception:
            pass
    return urls


def get_github_data(item: str, state: ScanState, git_token: str, ssl_verify: bool = True) -> None:
    """Fetch one GitHub content API *item*, decode and store in *state.git_data*."""
    headers = {"Authorization": "token " + git_token}
    try:
        raw = requests.get(item, verify=ssl_verify, timeout=(20, 20), headers=headers) \
                      .content.decode('utf-8')
        json_data = json.loads(raw)
        decoded = base64.b64decode(json_data['content'])
        text = unquote(unquote(str(decoded, 'utf-8'))).replace('\n', ' ')
        html_url = json_data.get('html_url', item).split("?ref=")[0]
        state.git_data[html_url] = text
    except (requests.ConnectionError, requests.exceptions.ReadTimeout):
        pass
