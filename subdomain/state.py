import threading
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class ScanState:
    """Holds all mutable scan results, replacing module-level globals."""
    js_link_list:   list = field(default_factory=list)
    final_set:      set  = field(default_factory=set)
    new_final_dict: dict = field(default_factory=dict)
    secret_dict:    dict = field(default_factory=lambda: defaultdict(list))
    git_data:       dict = field(default_factory=dict)
    cloud_url_set:  set  = field(default_factory=set)
    final_list:     list = field(default_factory=list)
    github_secrets: set  = field(default_factory=set)
    # Guards concurrent writes to secret_dict / github_secrets from multiple threads
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)
