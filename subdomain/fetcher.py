import re
from urllib.parse import unquote, urljoin

import requests
import termcolor
from bs4 import BeautifulSoup

from subdomain.state import ScanState


class JsExtract:
    """Fetch the target page and all external JavaScript files.

    Uses a persistent Session for connection pooling.
    """

    def __init__(self, state: ScanState, heads: dict, ssl_verify: bool = True):
        self.state = state
        self.session = requests.Session()
        self.session.headers.update(heads)
        if not ssl_verify:
            self.session.verify = False

    def FetchAndExtract(self, url: str) -> None:
        """Fetch *url* once, store inline content and collect external JS links."""
        if not (url.startswith('http://') or url.startswith('https://')):
            url = 'http://' + url

        print(termcolor.colored("Fetching page and searching for Javascripts...", color='yellow', attrs=['bold']))
        req = self.session.get(url, timeout=(20, 20))
        html = unquote(req.text)
        minhtml = re.sub(r'\s+', ' ', html).strip()
        self.state.final_list.append(minhtml)
        self.state.new_final_dict["Inline"] = minhtml
        print(termcolor.colored("Successfully got inline and external JS links.", color='blue', attrs=['bold']))
        if 'text/html' in req.headers.get('content-type', ''):
            soup = BeautifulSoup(html, features='html.parser')
            for link in soup.find_all('script'):
                if link.get('src'):
                    self.state.js_link_list.append(urljoin(url, link.get('src')))

    def SaveExtJsContent(self, js: str) -> None:
        """Fetch one external JS file and store its content."""
        try:
            content = unquote(self.session.get(js, timeout=(20, 20)).text)
            self.state.final_list.append(content)
            self.state.new_final_dict[str(js)] = content
        except Exception:
            pass
