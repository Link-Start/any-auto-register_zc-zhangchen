"""oauth_token_exchange 这条老路和 Codex 直连换 RT 的关系。

线上补 RT 的日志里，Codex 已经换到 refresh_token 之后，这条老路又拿另一条链路
的 code 试了 9 个 code_verifier，全是 400 token_exchange_user_error。除了看着
像失败，它还有个更危险的地方：万一某个候选真的 200 了但响应里没带
refresh_token，旧写法会用空串把到手的 RT 覆盖掉。
"""

import unittest

from platforms.chatgpt.protocol.auth_flow import AuthFlow


class _Result:
    def __init__(self, **kw):
        self.id_token = ""
        self.access_token = ""
        self.refresh_token = ""
        for key, value in kw.items():
            setattr(self, key, value)


class _Resp:
    status_code = 200
    text = "{}"
    headers: dict[str, str] = {}

    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


def _flow(result: _Result, payload: dict) -> tuple[AuthFlow, list]:
    """绕开 __init__，只装 oauth_token_exchange 用得到的东西。"""
    posted: list[dict] = []
    flow = AuthFlow.__new__(AuthFlow)
    flow.result = result
    flow._get_env = lambda key, default="": default
    flow._oauth_client_id = "app_test"
    flow._oauth_client_secret = ""
    flow._oauth_redirect_uri = "http://localhost:1455/auth/callback"
    flow._oauth_auth_url = ""
    flow._oauth_scope = ""
    flow._collect_code_verifier_candidates = lambda *_: [("captured", "v" * 43)]
    flow._sniff_login_verifier = lambda *_a, **_k: None
    flow._trace_http = lambda *_a, **_k: None

    class _Session:
        def post(self, url, headers=None, data=None, timeout=None):
            posted.append({"url": url, "data": data})
            return _Resp(payload)

    flow.session = _Session()
    return flow, posted


class OAuthTokenExchangeTests(unittest.TestCase):
    def test_skipped_once_a_refresh_token_is_already_in_hand(self):
        result = _Result(refresh_token="rt-from-codex")
        flow, posted = _flow(result, {"access_token": "at"})

        self.assertTrue(
            flow.oauth_token_exchange(
                "https://example.com/cb?code=abc", "https://example.com/cb?code=abc"
            )
        )
        self.assertEqual(posted, [])
        self.assertEqual(result.refresh_token, "rt-from-codex")

    def test_response_without_refresh_token_keeps_the_existing_one(self):
        # 直接调私有循环体走不到，这里让 result 先没有 RT、交换成功但响应缺字段
        result = _Result(id_token="id-old")
        flow, posted = _flow(result, {"access_token": "at-new"})

        self.assertTrue(
            flow.oauth_token_exchange(
                "https://example.com/cb?code=abc", "https://example.com/cb?code=abc"
            )
        )
        self.assertEqual(len(posted), 1)
        self.assertEqual(result.access_token, "at-new")
        self.assertEqual(result.id_token, "id-old")

    def test_still_runs_when_there_is_no_refresh_token_yet(self):
        result = _Result()
        flow, posted = _flow(result, {"access_token": "at", "refresh_token": "rt"})

        self.assertTrue(
            flow.oauth_token_exchange(
                "https://example.com/cb?code=abc", "https://example.com/cb?code=abc"
            )
        )
        self.assertEqual(len(posted), 1)
        self.assertEqual(result.refresh_token, "rt")


if __name__ == "__main__":
    unittest.main()
