from collections import Counter
from math import log2
from urllib.parse import urlparse

import tldextract
import termcolor


def entropy(s):
    """Shannon entropy of string s (0 = uniform, higher = more random)."""
    if not s:
        return 0.0
    return -sum(i / len(s) * log2(i / len(s)) for i in Counter(s).values())


def getDomain(url):
    """Return the registered domain (e.g. 'example.com') for a URL.

    Pure function — no side effects on any global state.
    """
    ext = tldextract.extract(str(url))
    return ext.top_domain_under_public_suffix


def tldExt(name):
    return tldextract.extract(name).top_domain_under_public_suffix


def tldSorting(subdomain_list):
    """Sort domain strings in lexicographic label order (a.example before z.example)."""
    reversed_labels = [".".join(str(item).split(".")[::-1]) for item in subdomain_list]
    sorted_reversed = sorted(reversed_labels)
    return [".".join(item.split(".")[::-1]) for item in sorted_reversed]


def logo():
    return r"""
   _____       __    ____                        _       _
  / ___/__  __/ /_  / __ \____  ____ ___  ____ _(_)___  (_)___  ___  _____
  \__ \/ / / / __ \/ / / / __ \/ __ `__ \/ __ `/ / __ \/ /_  / / _ \/ ___/
 ___/ / /_/ / /_/ / /_/ / /_/ / / / / / / /_/ / / / / / / / /_/  __/ /
/____/\__,_/_.___/_____/\____/_/ /_/ /_/\__,_/_/_/ /_/_/ /___/\___/_/

                                                              [ v3.0 ]
    Passive DNS  •  JS Secrets  •  GitHub Scan  •  Cloud URLs  •  Python API
    ─────────────────────────────────────────────────────────────────────────
"""


def printlogo():
    return termcolor.colored(logo(), color="red", attrs=["bold"])
