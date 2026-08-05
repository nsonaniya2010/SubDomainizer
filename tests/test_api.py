import json
import os
import tempfile

import pytest
import responses as responses_lib

from subdomain.api import Scanner, ScanConfig, ScanResult


# ── ScanResult ────────────────────────────────────────────────────────────────

def _make_result(**overrides):
    defaults = dict(
        subdomains=["api.example.com", "www.example.com"],
        cloud_urls=["mybucket.s3.amazonaws.com"],
        secrets={"https://example.com/app.js": ["api_key = abc123def456"]},
        github_secrets=["[GitHub Token] ghp_abc"],
        passive_dns={"crt.sh": ["mail.example.com"]},
    )
    defaults.update(overrides)
    return ScanResult(**defaults)


def test_scan_result_to_dict_shape():
    r = _make_result()
    d = r.to_dict()
    assert set(d.keys()) == {"subdomains", "cloud_urls", "secrets", "github_secrets", "passive_dns"}
    assert d["subdomains"] == ["api.example.com", "www.example.com"]
    assert d["cloud_urls"] == ["mybucket.s3.amazonaws.com"]
    assert "https://example.com/app.js" in d["secrets"]
    assert d["passive_dns"]["crt.sh"] == ["mail.example.com"]


def test_scan_result_to_json_is_valid():
    r = _make_result()
    raw = r.to_json()
    parsed = json.loads(raw)
    assert parsed["subdomains"] == r.subdomains
    assert parsed["github_secrets"] == r.github_secrets


def test_scan_result_to_json_custom_indent():
    r = _make_result()
    raw = r.to_json(indent=4)
    assert "\n    " in raw  # 4-space indent in output


def test_scan_result_empty():
    r = ScanResult(subdomains=[], cloud_urls=[], secrets={}, github_secrets=[], passive_dns={})
    d = r.to_dict()
    assert d["subdomains"] == []
    assert json.loads(r.to_json()) == d


# ── ScanConfig ────────────────────────────────────────────────────────────────

def test_scan_config_defaults():
    cfg = ScanConfig()
    assert cfg.ssl_verify is True
    assert cfg.cookie == ""
    assert cfg.github_token == ""
    assert cfg.passive is True
    assert cfg.verbose is True
    assert cfg.max_workers >= 1


def test_scan_config_custom_values():
    cfg = ScanConfig(cookie="session=abc", ssl_verify=False, github_token="ghp_x", passive=False)
    assert cfg.cookie == "session=abc"
    assert cfg.ssl_verify is False
    assert cfg.github_token == "ghp_x"
    assert cfg.passive is False


# ── Scanner construction ──────────────────────────────────────────────────────

def test_scanner_default_construction():
    s = Scanner()
    assert s.config is not None
    assert s._cloud_patterns
    assert s._generic_pat is not None
    assert s._specific_patterns
    assert s._ip_regex is not None
    assert s._custom_dom_regex is None


def test_scanner_custom_config_with_domains():
    cfg = ScanConfig(custom_domains="example.com,test.org")
    s = Scanner(cfg)
    assert s._custom_dom_regex is not None


# ── Scanner.scan_folder ───────────────────────────────────────────────────────

def test_scan_folder_empty_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        result = Scanner(ScanConfig(passive=False)).scan_folder(tmpdir)
    assert isinstance(result, ScanResult)
    assert isinstance(result.subdomains, list)
    assert isinstance(result.secrets, dict)
    assert result.passive_dns == {}


def test_scan_folder_detects_secret():
    content = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
    with tempfile.TemporaryDirectory() as tmpdir:
        fpath = os.path.join(tmpdir, "config.js")
        with open(fpath, "w") as f:
            f.write(content)
        result = Scanner(ScanConfig(passive=False, verbose=False)).scan_folder(tmpdir)
    assert any(fpath in k or os.path.normpath(fpath) in k for k in result.secrets), \
        f"Expected secret detected in {list(result.secrets.keys())}"


def test_scan_folder_single_file():
    content = "https://mybucket.s3.amazonaws.com/key"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
        f.write(content)
        fname = f.name
    try:
        result = Scanner(ScanConfig(passive=False, verbose=False)).scan_folder(fname)
        assert isinstance(result, ScanResult)
    finally:
        os.unlink(fname)


# ── Scanner.scan_urls (mocked HTTP) ──────────────────────────────────────────

@responses_lib.activate
def test_scan_url_returns_scan_result():
    responses_lib.add(
        responses_lib.GET, "http://example.com",
        body="<html><body><script>var x=1;</script></body></html>",
        content_type="text/html",
    )
    result = Scanner(ScanConfig(passive=False, verbose=False)).scan_url("http://example.com")
    assert isinstance(result, ScanResult)
    assert isinstance(result.subdomains, list)
    assert isinstance(result.cloud_urls, list)
    assert isinstance(result.secrets, dict)
    assert isinstance(result.github_secrets, list)
    assert isinstance(result.passive_dns, dict)


@responses_lib.activate
def test_scan_url_captures_subdomains():
    js_content = "var api = 'https://api.example.com/v1';"
    html = '<html><head><script src="/app.js"></script></head></html>'
    responses_lib.add(responses_lib.GET, "http://example.com", body=html, content_type="text/html")
    responses_lib.add(responses_lib.GET, "http://example.com/app.js", body=js_content,
                      content_type="application/javascript")

    cfg = ScanConfig(custom_domains="example.com", passive=False, verbose=False)
    result = Scanner(cfg).scan_url("http://example.com")
    assert any("example.com" in s for s in result.subdomains)


@responses_lib.activate
def test_scan_url_captures_cloud_urls():
    html = '<html><body><script>var b="mybucket.s3.amazonaws.com";</script></body></html>'
    responses_lib.add(responses_lib.GET, "http://example.com", body=html, content_type="text/html")

    result = Scanner(ScanConfig(passive=False, verbose=False)).scan_url("http://example.com")
    assert any("s3.amazonaws.com" in u for u in result.cloud_urls)


@responses_lib.activate
def test_scan_url_connection_error_returns_empty_result():
    responses_lib.add(
        responses_lib.GET, "http://unreachable.example.com",
        body=Exception("connection refused"),
    )
    result = Scanner(ScanConfig(passive=False, verbose=False)).scan_url("http://unreachable.example.com")
    assert isinstance(result, ScanResult)


@responses_lib.activate
def test_scan_urls_merges_results():
    html_a = '<html><body><script>var k="https://a.example.com";</script></body></html>'
    html_b = '<html><body><script>var k="https://b.example.com";</script></body></html>'
    responses_lib.add(responses_lib.GET, "http://a.example.com", body=html_a, content_type="text/html")
    responses_lib.add(responses_lib.GET, "http://b.example.com", body=html_b, content_type="text/html")

    cfg = ScanConfig(custom_domains="example.com", passive=False, verbose=False)
    result = Scanner(cfg).scan_urls(["http://a.example.com", "http://b.example.com"])
    assert isinstance(result, ScanResult)
    # Both target netlocs should appear in subdomains
    assert any("a.example.com" in s for s in result.subdomains)
    assert any("b.example.com" in s for s in result.subdomains)
