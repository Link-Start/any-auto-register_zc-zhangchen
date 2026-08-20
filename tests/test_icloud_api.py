"""iCloud HTTP 接口：前端依赖的响应结构与业务错误码到状态码的映射。"""

import base64
import os
from contextlib import contextmanager

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlmodel import SQLModel, create_engine

from platforms.icloud.credentials import ICloudCredentials
from platforms.icloud.errors import ICloudError
from platforms.icloud.models import ImportedSession, PrivateEmail


class _StubWebClient:
    def __init__(self, *, imported=None, private_emails=()):
        self.imported = imported
        self.private_emails = list(private_emails)
        self.deleted = []
        self.counter = 0

    def import_session(self, _request):
        return self.imported

    def list_private_emails(self, _credentials):
        return self.private_emails

    def generate_private_email(self, _credentials, *, label="", note=""):
        self.counter += 1
        return PrivateEmail(
            address=f"alias{self.counter}@icloud.com",
            provider_id=f"anon-{self.counter}",
            label=label,
            note=note,
        )

    def delete_private_email(self, _credentials, *, address, provider_id="", status=""):
        self.deleted.append(address)


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("CREDENTIAL_ENCRYPTION_KEY", base64.b64encode(os.urandom(32)).decode())

    import core.db as db
    import core.secret_box as secret_box_module
    from api.icloud import router
    from core.secret_box import SecretBox
    from services import icloud_service

    engine = create_engine(f"sqlite:///{tmp_path / 'icloud.db'}")
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(db, "engine", engine)
    monkeypatch.setattr(icloud_service, "engine", engine)
    monkeypatch.setattr(secret_box_module, "secret_box", SecretBox())
    monkeypatch.setattr(icloud_service, "secret_box", secret_box_module.secret_box)

    stub = _StubWebClient(
        imported=ImportedSession(
            credentials=ICloudCredentials(
                region="global",
                dsid="123456",
                cookies="a=1",
                hme_service_url="https://hme.example.test",
                imap_password="app-specific",
            ),
            account_email="owner@icloud.com",
            masked_dsid="12**56",
        )
    )

    @contextmanager
    def _factory(**_kwargs):
        yield stub

    monkeypatch.setattr(icloud_service, "web_client", _factory)

    app = FastAPI()
    app.include_router(router, prefix="/api")
    test_client = TestClient(app)
    test_client.stub = stub
    return test_client


def _import_account(client) -> dict:
    response = client.post("/api/icloud/accounts/import-cookie", json={"cookie_header": "a=1"})
    assert response.status_code == 200
    return response.json()


def test_import_cookie_then_generate_and_list_aliases(client):
    account = _import_account(client)
    assert account["email"] == "owner@icloud.com"
    assert account["quota"] == {
        "limit": 5,
        "used": 0,
        "remaining": 5,
        "reset_at": None,
    }

    created = client.post(
        "/api/icloud/aliases",
        json={"account_id": account["id"], "label": "任务", "count": 2},
    )
    assert created.status_code == 200
    addresses = [item["address"] for item in created.json()["items"]]
    assert addresses == ["alias1@icloud.com", "alias2@icloud.com"]

    listed = client.get("/api/icloud/aliases").json()["items"]
    assert [item["address"] for item in listed] == list(reversed(addresses))
    assert {item["account_email"] for item in listed} == {"owner@icloud.com"}

    accounts = client.get("/api/icloud/accounts").json()["items"]
    assert accounts[0]["alias_count"] == 2
    assert accounts[0]["quota"]["remaining"] == 3


def test_delete_alias_also_revokes_it_upstream(client):
    account = _import_account(client)
    alias = client.post("/api/icloud/aliases", json={"account_id": account["id"]}).json()["items"][0]

    response = client.request("DELETE", f"/api/icloud/aliases/{alias['id']}", params={"remote": True})

    assert response.status_code == 200
    assert client.stub.deleted == [alias["address"]]
    assert client.get("/api/icloud/aliases").json()["items"] == []


def test_disabled_account_cannot_generate_aliases(client):
    account = _import_account(client)
    client.patch(f"/api/icloud/accounts/{account['id']}", json={"enabled": False})

    response = client.post("/api/icloud/aliases", json={"account_email": "owner@icloud.com"})

    assert response.status_code == 409


def test_hourly_quota_maps_to_http_429(client):
    account = _import_account(client)
    client.post("/api/icloud/aliases", json={"account_id": account["id"], "count": 5})

    response = client.post("/api/icloud/aliases", json={"account_id": account["id"]})

    assert response.status_code == 429


def test_upstream_failure_maps_to_http_503(client, monkeypatch):
    from services import icloud_service

    account = _import_account(client)

    def _boom(*_args, **_kwargs):
        raise ICloudError("upstream_unavailable", "Apple 服务暂时不可用")

    monkeypatch.setattr(client.stub, "list_private_emails", _boom)

    response = client.post(f"/api/icloud/accounts/{account['id']}/sync")

    assert response.status_code == 503
    assert response.json()["detail"] == "Apple 服务暂时不可用"
    assert icloud_service.get_account(account["id"]).sync_error == "Apple 服务暂时不可用"


def test_apple_rejection_stays_in_4xx_so_the_reason_survives(client, monkeypatch):
    """Apple 明确拒绝要走 4xx。

    用 5xx 表达的话，Cloudflare 会把响应体换成自己的 "502 Bad gateway" 页面，
    Apple 给的原因就彻底没了——线上就是这么丢的。
    """
    account = _import_account(client)

    def _rejected(*_args, **_kwargs):
        raise ICloudError("upstream_rejected", "iCloud HME 拒绝了请求")

    monkeypatch.setattr(client.stub, "generate_private_email", _rejected)

    response = client.post("/api/icloud/aliases", json={"account_id": account["id"]})

    assert response.status_code == 422
    assert response.json()["detail"] == "iCloud HME 拒绝了请求"


def test_unknown_account_and_alias_map_to_http_404(client):
    assert client.post("/api/icloud/accounts/999/sync").status_code == 404
    assert client.request("DELETE", "/api/icloud/aliases/999").status_code == 404
    assert client.get("/api/icloud/aliases/999/messages").status_code == 404
