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
      _____       _     _____                        _       _
     / ____|     | |   |  __ \                      (_)     (_)
    | (___  _   _| |__ | |  | | ___  _ __ ___   __ _ _ _ __  _ _______ _ __
     \___ \| | | | '_ \| |  | |/ _ \| '_ ` _ \ / _` | | '_ \| |_  / _ \ '__|
     ____) | |_| | |_) | |__| | (_) | | | | | | (_| | | | | | |/ /  __/ |
    |_____/ \__,_|_.__/|_____/ \___/|_| |_| |_|\__,_|_|_| |_|_/___\___|_|Version 2.1
Find interesting Subdomains and secrets hidden in page, folder, External Javascripts and GitHub
"""


def printlogo():
    return termcolor.colored(logo(), color="red", attrs=["bold"])
