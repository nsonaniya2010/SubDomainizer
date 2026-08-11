[![Python 3.x](https://img.shields.io/badge/python-%3E3.6-yellow.svg)](https://www.python.org/) 
[![Twitter](https://img.shields.io/badge/twitter-@neeraj_sonaniya-blue.svg)](https://twitter.com/neeraj_sonaniya)

To secure your system with supply chain risks:

[![Centriole](https://centriole.io/public/badges/NVbDCY499Lo1AODgRPtkmEdJzYveqAdTq_NYShZ2myM.svg)](https://centriole.io)

## Buy Me A [Coffee](https://www.buymeacoffee.com/neerajson)

## SubDomainizer

SubDomainizer is a tool designed to find hidden subdomains and secrets present in either a webpage, GitHub, and external JavaScript files present in the given URL.
This tool also finds S3 buckets, CloudFront URLs and more from those JS files which could be interesting — like an S3 bucket open to read/write, subdomain takeover, and similar cases for CloudFront.
It also scans inside a given folder which contains your files.

## What's New in v3.0

- **Modular package architecture** — rewritten as a proper Python package (`subdomain/`) for maintainability and importability.
- **Programmatic API** — use `Scanner`, `ScanConfig`, and `ScanResult` directly from Python code (see [Python API](#python-api) below).
- **Passive subdomain enumeration** — automatically queries crt.sh (certificate transparency), Wayback Machine, and HudsonRock Cavalier on every scan, no extra flags needed.
- **Improved secrets detection** — smarter Shannon entropy filtering with a false-positive blacklist to reduce noise.
- **JSON output** (`-j` / `--json`) — print all results as structured JSON for piping into other tools.
- **Secrets output file** (`-sop` / `--secretop`) — save discovered secrets to a dedicated file.
- **Python 3.13 compatibility** fixes.

## Cloud Storage Services Supported

SubDomainizer can find URLs for the following cloud storage services:
```
1. Amazon AWS (CloudFront and S3 buckets)
2. DigitalOcean Spaces
3. Microsoft Azure
4. Google Cloud Services
5. Dreamhost
6. RackCDN
```

## Secret Key Searching (beta)

SubDomainizer will also find secrets present in the content of the page and JavaScript files.
Secret finding depends on specific keywords and the *Shannon Entropy* formula with false-positive filtering.
It is possible that some secrets found by the tool will be false positives.
This feature is in beta; later versions may improve accuracy.

## Screenshots

![SubDomainizer](https://i.imgur.com/x3XSamk.png)

![Sub2.0](https://i.imgur.com/TvVKabs.png)

## Installation Steps

1. Clone SubDomainizer from git:
```
git clone https://github.com/nsonaniya2010/SubDomainizer.git
```
2. Change the directory:
```
cd SubDomainizer
```
3. Install the requirements:
```
pip3 install -r requirements.txt
```

## Update to Latest Version

```
git pull
pip3 install -r requirements.txt
```

## Usage

Short Form    | Long Form              | Description
------------- | ---------------------- | -------------
-u            | --url                  | URL to scan for subdomains and secrets.
-l            | --listfile             | File containing a list of URLs to scan (one per line).
-o            | --output               | File to save discovered subdomains.
-c            | --cookie               | Cookie header value to include with requests.
-h            | --help                 | Show the help message and exit.
-cop          | --cloudop              | File to save discovered cloud service URLs.
-sop          | --secretop             | File to save discovered secrets.
-d            | --domains              | Comma-separated TLDs to extract subdomains for (e.g. `example.com,foo.com`).
-g            | --gitscan              | Enable GitHub scanning for subdomains and secrets.
-gt           | --gittoken             | GitHub API token (required with `-g`).
-gop          | --gitsecretop          | File to save secrets found on GitHub.
-j            | --json                 | Print all results as JSON to stdout.
-k            | --nossl                | Disable SSL certificate verification.
-f            | --folder               | Root folder to scan recursively.
-san          | --subject_alt_name     | Find Subject Alternative Names from TLS certs: `all` or `same`.

## SAN Options

* `all` — find all domains and subdomains from TLS certificates.
* `same` — find only subdomains belonging to the same TLD.

## CLI Examples

* Show help:
```
python3 SubDomainizer.py -h
```
* Scan a single URL:
```
python3 SubDomainizer.py -u https://www.example.com
```
* Scan a list of URLs from a file:
```
python3 SubDomainizer.py -l list.txt
```
* Save subdomains to a file:
```
python3 SubDomainizer.py -u https://www.example.com -o output.txt
```
* Use cookies:
```
python3 SubDomainizer.py -u https://www.example.com -c "test=1; test=2"
```
* Scan via GitHub:
```
python3 SubDomainizer.py -u https://www.example.com -o output.txt -gt <github_token> -g
```
* Disable SSL verification:
```
python3 SubDomainizer.py -u https://www.example.com -gt <github_token> -g -k
```
* Scan a local folder:
```
python3 SubDomainizer.py -f /path/to/folder/ -d example.com
```
* Subject Alternative Names:
```
python3 SubDomainizer.py -u https://www.example.com -san all
```
* Save secrets to separate files:
```
python3 SubDomainizer.py -u https://www.example.com -sop secrets.txt -gop github_secrets.txt -gt <github_token> -g
```
* Output results as JSON:
```
python3 SubDomainizer.py -u https://www.example.com -j
```

## Python API

SubDomainizer can be used directly as a Python library via the `Scanner`, `ScanConfig`, and `ScanResult` classes.

### Basic usage

```python
from subdomain import Scanner

result = Scanner().scan_url("https://example.com")
print(result.subdomains)    # list of discovered subdomains
print(result.cloud_urls)    # list of cloud service URLs
print(result.secrets)       # dict mapping source → [secret values]
print(result.passive_dns)   # dict mapping source → [subdomains from passive enum]
print(result.to_json())     # everything as a JSON string
```

### Advanced usage with `ScanConfig`

```python
from subdomain import Scanner, ScanConfig

config = ScanConfig(
    cookie="session=abc123",
    ssl_verify=True,
    github_token="ghp_...",
    custom_domains="example.com,foo.com",
    passive=True,
    verbose=False,
)

scanner = Scanner(config)

# Scan a single URL
result = scanner.scan_url("https://www.example.com")

# Scan multiple URLs (results are merged)
result = scanner.scan_urls(["https://a.example.com", "https://b.example.com"])

# Scan a local folder
result = scanner.scan_folder("/path/to/folder/")

# Serialize to JSON
with open("results.json", "w") as f:
    f.write(result.to_json())
```

### `ScanConfig` fields

Field           | Type   | Default   | Description
--------------- | ------ | --------- | -----------
`cookie`        | str    | `""`      | Cookie header value for requests.
`ssl_verify`    | bool   | `True`    | Verify SSL certificates.
`github_token`  | str    | `""`      | GitHub API token; enables GitHub scanning when set.
`custom_domains`| str    | `""`      | Comma-separated extra domains to extract subdomains for.
`san_mode`      | str    | `""`      | SAN mode: `"all"` or `"same"` (CLI only for now).
`max_workers`   | int    | auto      | Thread pool size (defaults to `min(32, cpu_count + 8)`).
`passive`       | bool   | `True`    | Run passive DNS enumeration (crt.sh, Wayback, HudsonRock).
`verbose`       | bool   | `True`    | Print progress to stdout.

### `ScanResult` fields

Field             | Type   | Description
----------------- | ------ | -----------
`subdomains`      | list   | All discovered subdomains (sorted).
`cloud_urls`      | list   | Cloud service URLs found (sorted).
`secrets`         | dict   | `{source: [secret, ...]}` mapping.
`github_secrets`  | list   | Secrets found in GitHub code (sorted).
`passive_dns`     | dict   | `{source: [subdomain, ...]}` from passive enumeration.

## Passive Subdomain Enumeration

Every scan automatically queries three unauthenticated public sources concurrently:

| Source           | What it queries |
| ---------------- | --------------- |
| **crt.sh**       | Certificate Transparency logs |
| **Wayback Machine** | CDX API archive (last 2 years) |
| **HudsonRock**   | Cavalier stealer-log URL database |

Results from passive enumeration are merged into the main subdomain list and also available separately under `result.passive_dns`.

## Difference in Results (with/without cookies on facebook.com)

Results before using Facebook cookies in SubDomainizer:

![BeforeCookies](https://i.imgur.com/v7igAId.png)

Results after using Facebook cookies in SubDomainizer:

![AfterCookies](https://i.imgur.com/QKY09mx.png)

## Changelog

### v3.0
1. Rewritten as a modular `subdomain/` Python package.
2. New programmatic API: `Scanner`, `ScanConfig`, `ScanResult`.
3. Passive subdomain enumeration via crt.sh, Wayback Machine, and HudsonRock.
4. Improved secrets detection with Shannon entropy and false-positive filtering.
5. `--json` / `-j` flag to output all results as JSON.
6. `--secretop` / `-sop` flag to save secrets to a file.
7. Python 3.13 compatibility fixes.

### v2.0
1. Find Subject Alternative Names for discovered subdomains.
2. Added source tracking for where secrets were found.

## License

This tool is licensed under the MIT license. See the [LICENSE](https://github.com/nsonaniya2010/SubDomainizer/blob/master/LICENSE) for details.

## Want to Help?

If you like this tool, consider supporting development:
[Help Here](https://paypal.me/BugsByNeeraj)
