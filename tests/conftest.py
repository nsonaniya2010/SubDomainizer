import pytest
from subdomain.state import ScanState
from subdomain.patterns.secrets import compile_generic_secret_regex, compile_specific_secret_patterns
from subdomain.patterns.cloud import compile_cloud_patterns


@pytest.fixture
def state():
    return ScanState()


@pytest.fixture(scope="session")
def generic_pat():
    return compile_generic_secret_regex()


@pytest.fixture(scope="session")
def specific_patterns():
    return compile_specific_secret_patterns()


@pytest.fixture(scope="session")
def cloud_patterns():
    return compile_cloud_patterns()
