"""Tests for passive subdomain enumeration (all HTTP calls mocked)."""
import json
import pytest
import responses as responses_lib

from subdomain.passive import (
    fetch_hudsonrock,
    fetch_crtsh,
    fetch_wayback,
    passive_enum,
    _extract_subdomains_from_urls,
    _walk_json_for_strings,
)


class TestExtractHelpers:
    def test_extract_from_simple_url_list(self):
        subs = _extract_subdomains_from_urls(
            ["https://api.example.com/v1", "https://login.example.com"],
            "example.com",
        )
        assert "api.example.com" in subs
        assert "login.example.com" in subs

    def test_extract_ignores_other_domains(self):
        subs = _extract_subdomains_from_urls(
            ["https://api.other.com/v1"],
            "example.com",
        )
        assert len(subs) == 0

    def test_walk_json_flat_dict(self):
        strings = _walk_json_for_strings({"url": "https://a.example.com", "id": 1})
        assert "https://a.example.com" in strings

    def test_walk_json_nested(self):
        data = {"data": {"items": [{"url": "https://b.example.com"}]}}
        strings = _walk_json_for_strings(data)
        assert "https://b.example.com" in strings

    def test_walk_json_list(self):
        strings = _walk_json_for_strings(["https://c.example.com", "other"])
        assert "https://c.example.com" in strings


class TestFetchCrtsh:
    @responses_lib.activate
    def test_extracts_subdomains_from_name_value(self):
        payload = [
            {"name_value": "api.example.com\nlogin.example.com", "common_name": "example.com"},
        ]
        responses_lib.add(
            responses_lib.GET,
            "https://crt.sh/?q=%.example.com&output=json&deduplicate=Y",
            json=payload,
        )
        subs = fetch_crtsh("example.com")
        assert "api.example.com" in subs
        assert "login.example.com" in subs

    @responses_lib.activate
    def test_strips_wildcard_prefix(self):
        payload = [{"name_value": "*.example.com", "common_name": "example.com"}]
        responses_lib.add(
            responses_lib.GET,
            "https://crt.sh/?q=%.example.com&output=json&deduplicate=Y",
            json=payload,
        )
        subs = fetch_crtsh("example.com")
        assert "example.com" in subs
        assert any("*" not in s for s in subs)

    @responses_lib.activate
    def test_returns_empty_on_http_error(self):
        responses_lib.add(
            responses_lib.GET,
            "https://crt.sh/?q=%.example.com&output=json&deduplicate=Y",
            status=500,
        )
        assert fetch_crtsh("example.com") == set()

    @responses_lib.activate
    def test_ignores_unrelated_domains(self):
        payload = [{"name_value": "sub.other.com", "common_name": "other.com"}]
        responses_lib.add(
            responses_lib.GET,
            "https://crt.sh/?q=%.example.com&output=json&deduplicate=Y",
            json=payload,
        )
        subs = fetch_crtsh("example.com")
        assert len(subs) == 0


class TestFetchWayback:
    @responses_lib.activate
    def test_extracts_hostnames_from_urls(self):
        body = "https://api.example.com/page\nhttps://cdn.example.com/asset.js\n"
        responses_lib.add(
            responses_lib.GET,
            "https://web.archive.org/cdx/search/cdx",
            body=body,

        )
        subs = fetch_wayback("example.com")
        assert "api.example.com" in subs
        assert "cdn.example.com" in subs

    @responses_lib.activate
    def test_returns_empty_on_error(self):
        responses_lib.add(
            responses_lib.GET,
            "https://web.archive.org/cdx/search/cdx",
            status=503,

        )
        assert fetch_wayback("example.com") == set()

    @responses_lib.activate
    def test_skips_blank_lines(self):
        body = "\n\nhttps://mail.example.com/inbox\n\n"
        responses_lib.add(
            responses_lib.GET,
            "https://web.archive.org/cdx/search/cdx",
            body=body,

        )
        subs = fetch_wayback("example.com")
        assert "mail.example.com" in subs


class TestFetchHudsonRock:
    @responses_lib.activate
    def test_extracts_subdomains_from_flat_list(self):
        payload = {"urls": ["https://portal.example.com/login", "https://dev.example.com"]}
        responses_lib.add(
            responses_lib.GET,
            "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/urls-by-domain",
            json=payload,
        )
        subs = fetch_hudsonrock("example.com")
        assert "portal.example.com" in subs
        assert "dev.example.com" in subs

    @responses_lib.activate
    def test_extracts_from_nested_json(self):
        payload = {"data": {"credentials": [{"url": "https://internal.example.com/auth"}]}}
        responses_lib.add(
            responses_lib.GET,
            "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/urls-by-domain",
            json=payload,
        )
        subs = fetch_hudsonrock("example.com")
        assert "internal.example.com" in subs

    @responses_lib.activate
    def test_returns_empty_on_error(self):
        responses_lib.add(
            responses_lib.GET,
            "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/urls-by-domain",
            status=429,
        )
        assert fetch_hudsonrock("example.com") == set()


class TestPassiveEnum:
    @responses_lib.activate
    def test_aggregates_all_sources(self):
        responses_lib.add(
            responses_lib.GET,
            "https://crt.sh/?q=%.example.com&output=json&deduplicate=Y",
            json=[{"name_value": "a.example.com", "common_name": "example.com"}],
        )
        responses_lib.add(
            responses_lib.GET,
            "https://web.archive.org/cdx/search/cdx",
            body="https://b.example.com/page\n",

        )
        responses_lib.add(
            responses_lib.GET,
            "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/urls-by-domain",
            json={"urls": ["https://c.example.com"]},
        )
        results = passive_enum("example.com")
        all_subs = set().union(*results.values())
        assert "a.example.com" in all_subs
        assert "b.example.com" in all_subs
        assert "c.example.com" in all_subs

    @responses_lib.activate
    def test_partial_failure_still_returns_others(self):
        responses_lib.add(
            responses_lib.GET,
            "https://crt.sh/?q=%.example.com&output=json&deduplicate=Y",
            status=500,
        )
        responses_lib.add(
            responses_lib.GET,
            "https://web.archive.org/cdx/search/cdx",
            body="https://ok.example.com/\n",

        )
        responses_lib.add(
            responses_lib.GET,
            "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/urls-by-domain",
            status=429,
        )
        results = passive_enum("example.com")
        assert "ok.example.com" in results.get("Wayback Machine", set())
