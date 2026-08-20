"""构建号过期导致的 "iCloud HME 拒绝了请求"。

Apple 会校验 clientBuildNumber。探测失败时代码回退到 constants.py 里的内置常量，
而那组常量会随 iCloud 发版过期（线上遇到过：内置 2626Build21，Apple 已经是
2630Build35）。此时 Apple 只回一个不带原因的 success:false，用户看到的就是
一句莫名其妙的"iCloud HME 拒绝了请求"，日志里也什么都没有。
"""

from __future__ import annotations

import json
import logging
from urllib.parse import parse_qs, urlparse

import pytest
import requests
from requests.adapters import BaseAdapter

from platforms.icloud.build_info import BuildInfo, BuildInfoCache
from platforms.icloud.constants import FALLBACK_CLOUD_BUILD
from platforms.icloud.credentials import ICloudCredentials
from platforms.icloud.errors import ICloudError
from platforms.icloud.transport import WebTransport
from platforms.icloud.web_client import ICloudWebClient

# 刻意和内置兜底常量不同：测的就是"兜底值被拒、换成探测值后成功"。
GOOD_BUILD = "9999Build1"


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
    """先给兜底值，invalidate 之后给探测到的真值。"""

    def __init__(self):
        super().__init__()
        self.discovered = False
        self.invalidated = 0

    def get(self, http, region):
        if self.discovered:
            return BuildInfo(cloud_build=GOOD_BUILD, cloud_mastering=GOOD_BUILD, discovered=True)
        return BuildInfo()  # discovered=False，即内置常量

    def invalidate(self, region):
        self.invalidated += 1
        self.discovered = True


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


def _build_number(request) -> str:
    return parse_qs(urlparse(request.url).query).get("clientBuildNumber", [""])[0]


def test_stale_build_number_is_retried_with_a_freshly_discovered_one():
    cache = _StubCache()

    def handler(request):
        # Apple 只认新构建号，旧的一律 success:false 且不说原因
        if _build_number(request) == GOOD_BUILD:
            return 200, {"success": True, "result": {"hme": "ok.alias@icloud.com"}}
        return 200, {"success": False}

    client, adapter = _client(handler, cache)
    result = client._hme_request(_credentials(), "POST", "v1/hme/generate", {"langCode": "en-us"})

    assert result == {"hme": "ok.alias@icloud.com"}
    assert cache.invalidated == 1, "拒绝后应该强制重新探测构建号"
    assert [_build_number(r) for r in adapter.requests] == [FALLBACK_CLOUD_BUILD, GOOD_BUILD]


def test_rejection_with_fresh_build_number_is_not_retried():
    """构建号本来就是探测到的，那拒绝就是真的拒绝，不该再重试一次。"""
    cache = _StubCache()
    cache.discovered = True

    client, adapter = _client(lambda _r: (200, {"success": False}), cache)

    with pytest.raises(ICloudError) as excinfo:
        client._hme_request(_credentials(), "POST", "v1/hme/generate", {})

    assert excinfo.value.code == "upstream_rejected"
    assert cache.invalidated == 0
    assert len(adapter.requests) == 1


def test_rejection_logs_apples_raw_envelope(caplog):
    """面向用户的文案是收敛过的，排查得靠日志里的原文。"""
    cache = _StubCache()
    cache.discovered = True
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
        '<html data-cw-private-build-number="9999Build1" '
        'data-cw-private-mastering-number="9999Build1"></html>'
    )

    class _Ok:
        def get(self, *_args, **_kwargs):
            response = requests.Response()
            response.status_code = 200
            response._content = html.encode()
            return response

    info = BuildInfoCache().get(_Ok(), "global")

    assert info.discovered is True
    assert info.cloud_build == "9999Build1"
