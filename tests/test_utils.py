import pytest
from subdomain.utils import entropy, getDomain, tldSorting
from subdomain.patterns.secrets import is_generic_placeholder


class TestEntropy:
    def test_uniform_string_is_zero(self):
        assert entropy("aaaaaaaa") == 0.0

    def test_high_entropy_random_string(self):
        assert entropy("aAbBcC1!xYzQ9@#") > 3.0

    def test_empty_string_returns_zero(self):
        assert entropy("") == 0.0

    def test_two_distinct_chars_half_entropy(self):
        # 4 'a' and 4 'b' → entropy = 1.0
        assert abs(entropy("aaaabbbb") - 1.0) < 1e-9


class TestIsGenericPlaceholder:
    def test_short_value_is_placeholder(self):
        assert is_generic_placeholder("abc") is True

    def test_null_literal(self):
        assert is_generic_placeholder("null") is True

    def test_undefined_literal(self):
        assert is_generic_placeholder("undefined") is True

    def test_example_substring(self):
        assert is_generic_placeholder("your_api_key_here_example") is True

    def test_placeholder_keyword(self):
        assert is_generic_placeholder("PLACEHOLDER_VALUE") is True

    def test_test_keyword(self):
        assert is_generic_placeholder("test_secret_value") is True

    def test_real_looking_key_is_not_placeholder(self):
        assert is_generic_placeholder("sk-prod-realkey1234567890") is False

    def test_real_looking_hex_is_not_placeholder(self):
        assert is_generic_placeholder("a3f9c2b7e0d14a58") is False

    # ── New false-positive filters ────────────────────────────────────────

    def test_property_access_is_placeholder(self):
        assert is_generic_placeholder("t.getMpConfig") is True

    def test_deep_property_access_is_placeholder(self):
        assert is_generic_placeholder("Ba.readFileSync") is True

    def test_nested_property_access_is_placeholder(self):
        assert is_generic_placeholder("Nt.withCredentials") is True

    def test_js_negation_prefix_is_placeholder(self):
        assert is_generic_placeholder("!!M0.withCredentials") is True

    def test_bitwise_not_prefix_is_placeholder(self):
        assert is_generic_placeholder("~someValue123") is True

    def test_pure_lowercase_identifier_is_placeholder(self):
        assert is_generic_placeholder("first_name") is True

    def test_camel_case_identifier_is_placeholder(self):
        assert is_generic_placeholder("withCredentials") is True

    def test_long_camel_case_identifier_is_placeholder(self):
        assert is_generic_placeholder("DevtoolsExtension") is True

    def test_kebab_case_identifier_is_placeholder(self):
        assert is_generic_placeholder("same-origin") is True

    def test_screaming_snake_no_digits_is_placeholder(self):
        assert is_generic_placeholder("WEBHOOK_SECRET_ROTATED") is True

    def test_url_path_is_placeholder(self):
        assert is_generic_placeholder("/aadhaar/authentication/v1") is True

    def test_http_url_is_not_caught_by_property_rule(self):
        # Full URL with scheme should pass the property-access dot check
        # (uses a domain not present in the blacklist)
        assert is_generic_placeholder("https://api.production.io/v1") is False

    def test_real_token_with_digits_survives(self):
        assert is_generic_placeholder("realKey1Abc9xyz5") is False


class TestGetDomain:
    def test_simple_url(self):
        assert getDomain("https://sub.example.com/path") == "example.com"

    def test_url_no_scheme(self):
        assert getDomain("sub.example.co.uk") == "example.co.uk"

    def test_root_domain(self):
        assert getDomain("https://example.com") == "example.com"

    def test_pure_function_no_side_effects(self):
        # Calling getDomain twice with same arg should yield same result (pure)
        r1 = getDomain("https://api.github.com")
        r2 = getDomain("https://api.github.com")
        assert r1 == r2 == "github.com"


class TestTldSorting:
    def test_sorts_in_label_order(self):
        result = tldSorting(["z.example.com", "a.example.com", "m.example.com"])
        assert result == ["a.example.com", "m.example.com", "z.example.com"]

    def test_single_item(self):
        assert tldSorting(["example.com"]) == ["example.com"]

    def test_different_tlds(self):
        result = tldSorting(["b.foo.com", "a.bar.com"])
        # 'a.bar.com' reversed = 'com.bar.a' < 'com.foo.b'
        assert result[0] == "a.bar.com"
