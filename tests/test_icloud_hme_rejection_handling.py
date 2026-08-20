""""iCloud HME 拒绝了请求" 的可观测性与抖动重试。

线上现象：刚做完两步验证后的头一两次生成隐私邮箱，Apple 偶发回一个不带原因的
success:false（对外表现为 502），隔几分钟用同一份凭据就能成功。当时两端都没有
日志，只剩一句"iCloud HME 拒绝了请求"，无从排查。

这里覆盖两件事：把 Apple 的原始信封记进日志；对没有副作用的动作重试一次。
另外构建号探测失败会静默降级到内置常量，同样需要日志（构建号本身经实测不是
上述拒绝的原因，但降级无声无息迟早咬人）。
"""

from __future__ import annotations

import json
import logging

import pytest
import requests
from requests.adapters import BaseAdapter

from platforms.icloud.build_info import BuildInfo, BuildInfoCache
from platforms.icloud.constants import FALLBACK_CLOUD_BUILD
from platforms.icloud.credentials import ICloudCredentials
from platforms.icloud.errors import ICloudError
from platforms.icloud.transport import WebTransport
from platforms.icloud.web_client import ICloudWebClient

DISCOVERED_BUILD = "9999Build1"


class _Adapter(BaseAdapter):
    def __init__(self, handler):
        super().__init__()
        self.handler = handler
        self.requests = []

    def send(self, request, **_kwargs):
        self.requests.append(request)
        status, payload = self.handler(request)
        response = requests.Response()
        response.status_code = status
        response._content = (
            payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        )
        response.url = request.url
        response.request = request
        response.headers.update({"Content-Type": "application/json"})
        return response

    def close(self):
        pass


class _StubCache(BuildInfoCache):
    """不去抓 Apple 页面，只记录有没有被要求重新探测。"""

    def __init__(self):
        super().__init__()
        self.invalidated = 0

    def get(self, http, region):
        return BuildInfo()

    def invalidate(self, region):
        self.invalidated += 1


def _credentials() -> ICloudCredentials:
    return ICloudCredentials.from_dict(
        {
            "region": "global",
            "dsid": "123456",
            "cookies": 'session=value; X-APPLE-WEBAUTH-USER="v=1%3As=1%3Ad=123456"',
            "hme_service_url": "https://p1-maildomainws.icloud.com/v1/hme",
            "client_id": "client-1",
            "client_build_number": FALLBACK_CLOUD_BUILD,
            "client_mastering_number": FALLBACK_CLOUD_BUILD,
        }
    )


def _client(handler, cache):
    adapter = _Adapter(handler)
    session = requests.Session()
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return ICloudWebClient(WebTransport(session=session), cache), adapter


def test_transient_rejection_of_generate_is_retried_once():
    """generate 只是让 Apple 提议地址，没有副作用，抖动时重试一次。"""
    cache = _StubCache()
    attempts = {"n": 0}

    def handler(_request):
        attempts["n"] += 1
        if attempts["n"] == 1:
            return 200, {"success": False}  # Apple 偶发拒绝，且不说原因
        return 200, {"success": True, "result": {"hme": "ok.alias@icloud.com"}}

    client, adapter = _client(handler, cache)
    result = client._hme_request(_credentials(), "POST", "v1/hme/generate", {"langCode": "en-us"})

    assert result == {"hme": "ok.alias@icloud.com"}
    assert len(adapter.requests) == 2
    assert cache.invalidated == 1, "重试时应顺带强制重新探测构建号"


def test_reserve_is_never_retried():
    """reserve 会真正占用地址，重试可能凭空多出一个隐私邮箱。"""
    cache = _StubCache()
    client, adapter = _client(lambda _r: (200, {"success": False}), cache)

    with pytest.raises(ICloudError) as excinfo:
        client._hme_request(_credentials(), "POST", "v1/hme/reserve", {"hme": "a@icloud.com"})

    assert excinfo.value.code == "upstream_rejected"
    assert len(adapter.requests) == 1
    assert cache.invalidated == 0


def test_delete_is_never_retried():
    cache = _StubCache()
    client, adapter = _client(lambda _r: (200, {"success": False}), cache)

    with pytest.raises(ICloudError):
        client._hme_request(_credentials(), "POST", "v1/hme/delete", {"anonymousId": "x"})

    assert len(adapter.requests) == 1


def test_persistent_rejection_still_surfaces_after_the_retry():
    cache = _StubCache()
    client, adapter = _client(lambda _r: (200, {"success": False}), cache)

    with pytest.raises(ICloudError) as excinfo:
        client._hme_request(_credentials(), "POST", "v1/hme/generate", {})

    assert excinfo.value.code == "upstream_rejected"
    assert len(adapter.requests) == 2, "重试一次之后就该把错误抛出去"


def test_rejection_logs_apples_raw_envelope(caplog):
    """面向用户的文案是收敛过的，排查得靠日志里的原文。"""
    cache = _StubCache()
    client, _ = _client(
        lambda _r: (200, {"success": False, "error": {"code": "ZONE_NOT_ENABLED"}}), cache
    )

    with caplog.at_level(logging.ERROR, logger="platforms.icloud.web_client"):
        with pytest.raises(ICloudError):
            client._hme_request(_credentials(), "POST", "v1/hme/generate", {})

    assert "ZONE_NOT_ENABLED" in caplog.text


def test_discovery_failure_is_logged_and_marked_as_fallback(caplog):
    """探测失败不能悄悄降级——那组常量迟早让 Apple 拒绝请求。"""

    class _Dead:
        def get(self, *_args, **_kwargs):
            raise requests.ConnectionError("boom")

    cache = BuildInfoCache()
    with caplog.at_level(logging.WARNING, logger="platforms.icloud.build_info"):
        info = cache.get(_Dead(), "global")

    assert info.discovered is False
    assert "构建号探测失败" in caplog.text


def test_discovered_build_info_is_marked():
    html = (
        f'<html data-cw-private-build-number="{DISCOVERED_BUILD}" '
        f'data-cw-private-mastering-number="{DISCOVERED_BUILD}"></html>'
    )

    class _Ok:
        def get(self, *_args, **_kwargs):
            response = requests.Response()
            response.status_code = 200
            response._content = html.encode()
            return response

    info = BuildInfoCache().get(_Ok(), "global")

    assert info.discovered is True
    assert info.cloud_build == DISCOVERED_BUILD
