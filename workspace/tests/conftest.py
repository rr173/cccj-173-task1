"""pytest 测试固件：内存库 + 可控时钟 + TestClient。"""
import pytest
from fastapi.testclient import TestClient

from app.api import create_app
from app.gateway import SpoolTransport, Gateway
from app.storage import Store


class FakeClock:
    def __init__(self, t=1_700_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds
        return self.t


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def gw(clock, tmp_path):
    store = Store(":memory:", clock=clock)
    transport = SpoolTransport(str(tmp_path / "spool"), clock=clock)
    return Gateway(store, transport)


@pytest.fixture
def client(gw):
    app = create_app(gateway=gw)
    return TestClient(app)


@pytest.fixture
def bootstrapped(gw):
    """建好 CA / 域信任 / 三个托管身份 + 一个外部证书伙伴域。"""
    gw.create_ca("corp-root")
    gw.create_ca("partner-root")
    gw.set_domain_trust("corp.example", "corp-root")
    gw.set_domain_trust("partner.example", "partner-root")
    gw.issue_identity("alice@corp.example", "corp-root")
    gw.issue_identity("bob@corp.example", "corp-root")
    gw.issue_identity("carol@partner.example", "partner-root")
    return gw
