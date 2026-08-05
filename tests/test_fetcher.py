import responses as responses_lib
import pytest
import requests
from subdomain.state import ScanState
from subdomain.fetcher import JsExtract

_HEADS = {"User-agent": "Mozilla/5.0"}


class TestJsExtract:
    @responses_lib.activate
    def test_fetch_and_extract_stores_inline(self):
        html = '<html><body><script>var x=1;</script></body></html>'
        responses_lib.add(responses_lib.GET, "http://example.com", body=html,
                          content_type="text/html")
        state = ScanState()
        js = JsExtract(state, _HEADS, ssl_verify=True)
        js.FetchAndExtract("http://example.com")
        assert state.new_final_dict.get("Inline") is not None

    @responses_lib.activate
    def test_fetch_and_extract_collects_external_scripts(self):
        html = '<html><head><script src="/app.js"></script></head></html>'
        responses_lib.add(responses_lib.GET, "http://example.com", body=html,
                          content_type="text/html")
        state = ScanState()
        js = JsExtract(state, _HEADS, ssl_verify=True)
        js.FetchAndExtract("http://example.com")
        assert any("/app.js" in link for link in state.js_link_list)

    @responses_lib.activate
    def test_save_ext_js_content_stores_content(self):
        responses_lib.add(responses_lib.GET, "http://example.com/app.js",
                          body="var secret='abc';", content_type="application/javascript")
        state = ScanState()
        js = JsExtract(state, _HEADS, ssl_verify=True)
        js.SaveExtJsContent("http://example.com/app.js")
        assert "http://example.com/app.js" in state.new_final_dict

    @responses_lib.activate
    def test_save_ext_js_content_handles_error_silently(self):
        responses_lib.add(responses_lib.GET, "http://example.com/broken.js",
                          body=requests.exceptions.ConnectionError("fail"))
        state = ScanState()
        js = JsExtract(state, _HEADS, ssl_verify=True)
        js.SaveExtJsContent("http://example.com/broken.js")  # must not raise
        assert "http://example.com/broken.js" not in state.new_final_dict

    @responses_lib.activate
    def test_url_without_scheme_gets_http_prepended(self):
        html = '<html><body>hi</body></html>'
        responses_lib.add(responses_lib.GET, "http://example.com", body=html,
                          content_type="text/html")
        state = ScanState()
        js = JsExtract(state, _HEADS, ssl_verify=True)
        js.FetchAndExtract("example.com")  # no scheme
        assert "Inline" in state.new_final_dict
