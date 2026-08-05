import re
import pytest
from subdomain.state import ScanState
from subdomain.extractor import (
    compile_ip_regex, compile_domain_regex, compile_custom_domains_regex,
    get_info_from_data,
)
from subdomain.patterns.secrets import compile_generic_secret_regex, compile_specific_secret_patterns
from subdomain.patterns.cloud import compile_cloud_patterns


@pytest.fixture
def scan_kwargs():
    """Return kwargs shared by many get_info_from_data calls."""
    return dict(
        cloudlist=compile_cloud_patterns(),
        generic_pat=compile_generic_secret_regex(),
        specific_patterns=compile_specific_secret_patterns(),
        ip_regex=compile_ip_regex(),
        custom_domains_regex=None,
        github_out=None,
    )


class TestGetInfoFromData:
    def test_aws_key_lands_in_secret_dict(self, state, scan_kwargs):
        content = "var key = 'AKIAIOSFODNN7EXAMPLE';"
        get_info_from_data("http://example.com/app.js", content, state, **scan_kwargs,
                           domain_regex=None)
        entries = state.secret_dict["http://example.com/app.js"]
        assert any("[AWS Access Key ID]" in e for e in entries)

    def test_s3_url_lands_in_cloud_set(self, state, scan_kwargs):
        content = "var url = 'https://mybucket.s3.amazonaws.com/file.txt';"
        get_info_from_data("http://example.com/app.js", content, state, **scan_kwargs,
                           domain_regex=None)
        assert any("s3.amazonaws.com" in u or "amazonaws.com" in u for u in state.cloud_url_set)

    def test_subdomain_added_to_final_set(self, state, scan_kwargs):
        content = "fetch('https://api.example.com/v1/data');"
        domain_regex = compile_domain_regex("example.com")
        get_info_from_data("http://example.com/app.js", content, state, **scan_kwargs,
                           domain_regex=domain_regex)
        assert "api.example.com" in state.final_set

    def test_no_regex_no_exception(self, state, scan_kwargs):
        content = "var x = 1;"
        get_info_from_data("http://example.com/app.js", content, state, **scan_kwargs,
                           domain_regex=None)

    def test_github_secret_added_when_github_url(self, scan_kwargs):
        state = ScanState()
        scan_kwargs = dict(scan_kwargs)
        scan_kwargs['github_out'] = "output.txt"
        content = "var key = 'AKIAIOSFODNN7EXAMPLE';"
        get_info_from_data("https://github.com/user/repo/blob/main/file.js", content, state,
                           **scan_kwargs, domain_regex=None)
        assert len(state.github_secrets) > 0

    def test_generic_placeholder_not_added(self, state, scan_kwargs):
        content = 'var api_key = "your_api_key_here";'
        get_info_from_data("http://example.com/app.js", content, state, **scan_kwargs,
                           domain_regex=None)
        for entry in state.secret_dict["http://example.com/app.js"]:
            assert "your_api_key_here" not in entry

    def test_key_equals_value_not_added(self, state, scan_kwargs):
        # APP_API_KEY_CREATED="APP_API_KEY_CREATED" should be filtered
        content = 'APP_API_KEY_CREATED="APP_API_KEY_CREATED"'
        get_info_from_data("http://example.com/app.js", content, state, **scan_kwargs,
                           domain_regex=None)
        entries = state.secret_dict["http://example.com/app.js"]
        assert not any("APP_API_KEY_CREATED" in e for e in entries)

    def test_property_access_value_not_added(self, state, scan_kwargs):
        # token=t.getMpConfig — property access value should be filtered
        content = 'var token=t.getMpConfig;'
        get_info_from_data("http://example.com/app.js", content, state, **scan_kwargs,
                           domain_regex=None)
        entries = state.secret_dict["http://example.com/app.js"]
        assert not any("getMpConfig" in e for e in entries)

    def test_pure_identifier_value_not_added(self, state, scan_kwargs):
        # token:"first_name" — pure word identifier should be filtered
        content = 'token:"first_name"'
        get_info_from_data("http://example.com/app.js", content, state, **scan_kwargs,
                           domain_regex=None)
        entries = state.secret_dict["http://example.com/app.js"]
        assert not any("first_name" in e for e in entries)

    def test_jwt_detected(self, state, scan_kwargs):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        content = f"var token = '{jwt}';"
        get_info_from_data("http://example.com/app.js", content, state, **scan_kwargs,
                           domain_regex=None)
        entries = state.secret_dict["http://example.com/app.js"]
        assert any("[JSON Web Token]" in e for e in entries)

    def test_custom_domain_regex_adds_subdomain(self, state, scan_kwargs):
        content = "redirect('https://login.mycompany.io/auth');"
        custom_regex = compile_custom_domains_regex("mycompany.io")
        kwargs = dict(scan_kwargs)
        kwargs['custom_domains_regex'] = custom_regex
        get_info_from_data("http://other.com/app.js", content, state, **kwargs,
                           domain_regex=None)
        assert any("mycompany.io" in s for s in state.final_set)


class TestCompileDomainRegex:
    def test_matches_subdomain(self):
        r = compile_domain_regex("example.com")
        assert r.search("api.example.com") is not None

    def test_does_not_match_other_domain(self):
        r = compile_domain_regex("example.com")
        assert r.search("api.other.com") is None


class TestCompileIpRegex:
    def test_matches_valid_ip(self):
        r = compile_ip_regex()
        assert r.search("192.168.1.1") is not None

    def test_matches_loopback(self):
        r = compile_ip_regex()
        assert r.search("127.0.0.1") is not None

    def test_does_not_match_invalid_ip(self):
        r = compile_ip_regex()
        assert r.search("999.999.999.999") is None


class TestCompileCustomDomainsRegex:
    def test_matches_single_domain(self):
        r = compile_custom_domains_regex("myco.io")
        assert r.search("app.myco.io") is not None

    def test_matches_multiple_domains(self):
        r = compile_custom_domains_regex("foo.com,bar.io")
        assert r.search("api.foo.com") is not None
        assert r.search("cdn.bar.io") is not None
