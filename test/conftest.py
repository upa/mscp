import pytest

def pytest_addoption(parser):
    parser.addoption("--mscp-path", default = "mscp",
                     help = "path to mscp binary")

@pytest.fixture
def mscp(request):
    return request.config.getoption("--mscp-path")
