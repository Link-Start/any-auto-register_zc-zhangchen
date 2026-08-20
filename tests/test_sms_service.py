import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from services import sms_service
from services.sms_service import (
    SMS_DEFAULT_COUNTRY,
    SMS_DEFAULT_SERVICE,
    PhoneCallbackController,
    SmsActivateProvider,
    SmsActivation,
    build_phone_callback,
    country_label,
    create_sms_provider,
    resolve_sms_settings,
)


class _Resp:
    def __init__(self, text="", payload=None, status_code=200):
        self.text = text
        self._payload = payload
        self.status_code = status_code

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload

    def raise_for_status(self):
        return None


class _IsolatedCacheMixin:
    """接码号码复用缓存是模块级全局 + 磁盘文件，测试之间必须隔离。"""

    def setUp(self):
        super().setUp()
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        cache_path = Path(self._tmp.name) / "cache.json"
        patcher = mock.patch.object(sms_service, "_cache_file", lambda: cache_path)
        patcher.start()
        self.addCleanup(patcher.stop)
        sms_service._SMS_CACHE = None
        self.addCleanup(setattr, sms_service, "_SMS_CACHE", None)
        self.cache_path = cache_path


class SmsHelperTests(unittest.TestCase):
    def test_status_text_parsing(self):
        parse = sms_service._parse_sms_status_text
        self.assertEqual(parse("STATUS_WAIT_CODE"), {"status": "wait_code"})
        self.assertEqual(parse("STATUS_OK:123456")["code"], "123456")
        self.assertEqual(parse("STATUS_CANCEL")["status"], "cancel")
        self.assertEqual(parse("STATUS_WAIT_RETRY:111")["status"], "wait_retry")
        self.assertEqual(parse("BAD_KEY"), {"status": "unknown", "raw": "BAD_KEY"})

    def test_safe_bool_treats_chinese_negative_as_false(self):
        safe_bool = sms_service._safe_bool
        self.assertTrue(safe_bool("1", False))
        self.assertTrue(safe_bool(True, False))
        self.assertFalse(safe_bool("否", True))
        self.assertFalse(safe_bool("off", True))
        self.assertTrue(safe_bool(None, True))
        self.assertFalse(safe_bool("", False))

    def test_country_label_falls_back_to_bare_id(self):
        self.assertEqual(country_label("52"), "52 泰国")
        self.assertEqual(country_label("99999"), "99999")

    def test_phone_number_is_normalised_to_e164(self):
        fmt = SmsActivateProvider._format_phone
        self.assertEqual(fmt({"phoneNumber": "+66123", "countryPhoneCode": "66"}), "+66123")
        self.assertEqual(fmt({"phoneNumber": "66123", "countryPhoneCode": "66"}), "+66123")
        self.assertEqual(fmt({"phoneNumber": "123", "countryPhoneCode": "66"}), "+66123")
        self.assertEqual(fmt({"phoneNumber": "123"}), "+123")

    def test_sms_candidate_rejects_placeholder_codes(self):
        self.assertIsNone(sms_service._make_sms_candidate("1", "v2", "null"))
        self.assertIsNone(sms_service._make_sms_candidate("1", "v2", ""))
        self.assertEqual(
            sms_service._make_sms_candidate("1", "v2", "123456")["code"], "123456"
        )


class TopCountryTests(unittest.TestCase):
    def setUp(self):
        self.provider = SmsActivateProvider(api_key="k")

    def test_parses_dict_and_list_shapes(self):
        rows = SmsActivateProvider._parse_top_countries(
            {"52": {"price": 0.2, "count": 300}, "not-a-country": {"price": 1}}
        )
        self.assertEqual(rows, [{"country": "52", "price": 0.2, "count": 300}])

        rows = SmsActivateProvider._parse_top_countries(
            [{"country": 16, "cost": 1.5, "qty": 10}, {"price": 1}]
        )
        self.assertEqual(rows, [{"country": "16", "price": 1.5, "count": 10}])

    def test_ranking_sorts_by_price_then_stock(self):
        payload = {
            "52": {"price": 0.3, "count": 10},
            "16": {"price": 0.1, "count": 5},
            "62": {"price": 0.3, "count": 90},
        }
        with mock.patch.object(self.provider, "_request", return_value=_Resp(payload=payload)):
            rows = self.provider.get_top_countries(service="dr")

        self.assertEqual([r["country"] for r in rows], ["16", "62", "52"])

    def test_ranking_falls_back_to_get_prices(self):
        prices = {"52": {"dr": {"cost": 0.4, "count": 12}}, "16": {"dr": {"cost": 0.2, "count": 0}}}
        with mock.patch.object(self.provider, "_request", side_effect=RuntimeError("boom")), \
                mock.patch.object(self.provider, "get_prices", return_value=prices):
            rows = self.provider.get_top_countries(service="dr")

        # 库存为 0 的国家被过滤掉
        self.assertEqual(rows, [{"country": "52", "price": 0.4, "count": 12}])

    def test_best_country_honours_stock_and_price_limits(self):
        rows = [
            {"country": "16", "price": 0.1, "count": 3},
            {"country": "52", "price": 0.5, "count": 300},
        ]
        with mock.patch.object(self.provider, "get_top_countries", return_value=rows):
            self.assertEqual(self.provider.get_best_country(min_stock=20), "52")
            self.assertIsNone(self.provider.get_best_country(min_stock=1, max_price=0.05))
            # 库存门槛没人满足时退到库存 >= 1 再挑一遍
            self.assertEqual(self.provider.get_best_country(min_stock=1000), "16")

    def test_strict_whitelist_only_picks_openai_sms_countries(self):
        rows = [
            {"country": "16", "price": 0.1, "count": 300},
            {"country": "52", "price": 0.9, "count": 300},
        ]
        with mock.patch.object(self.provider, "get_top_countries", return_value=rows):
            self.assertEqual(self.provider.get_best_country(strict_whitelist=True), "52")
            self.assertEqual(self.provider.get_best_country(strict_whitelist=False), "16")

    def test_allowed_countries_take_priority_over_whitelist(self):
        rows = [
            {"country": "16", "price": 0.1, "count": 300},
            {"country": "62", "price": 0.2, "count": 300},
            {"country": "52", "price": 0.9, "count": 300},
        ]
        with mock.patch.object(self.provider, "get_top_countries", return_value=rows):
            self.assertEqual(
                self.provider.get_best_country(allowed_countries=["62", "52"]), "62"
            )

    def test_ranking_failure_yields_no_country(self):
        with mock.patch.object(
            self.provider, "get_top_countries", side_effect=RuntimeError("网络错误")
        ):
            self.assertIsNone(self.provider.get_best_country())


class ProviderRequestTests(_IsolatedCacheMixin, unittest.TestCase):
    def test_balance_parsing(self):
        provider = SmsActivateProvider(api_key="k")
        with mock.patch.object(provider, "_request", return_value=_Resp("ACCESS_BALANCE:12.5")):
            self.assertEqual(provider.get_balance(), 12.5)
        with mock.patch.object(provider, "_request", return_value=_Resp("BAD_KEY")):
            with self.assertRaises(RuntimeError):
                provider.get_balance()

    def test_fixed_price_uses_provider_specific_parameters(self):
        smsbower = SmsActivateProvider(api_key="k", fixed_price=0.5)
        with mock.patch.object(
            smsbower, "_request", return_value=_Resp(payload={"activationId": "1", "phoneNumber": "66123"})
        ) as req:
            smsbower._request_number("getNumberV2", "dr", "52")
        params = req.call_args.args[0]
        self.assertEqual(params["minPrice"], 0.5)
        self.assertEqual(params["maxPrice"], 0.5)

        hero = SmsActivateProvider(
            api_key="k", base_url="https://hero-sms.com/stubs/handler_api.php", fixed_price=0.5
        )
        with mock.patch.object(
            hero, "_request", return_value=_Resp(payload={"activationId": "1", "phoneNumber": "66123"})
        ) as req:
            hero._request_number("getNumberV2", "dr", "52")
        params = req.call_args.args[0]
        self.assertEqual(params["fixedPrice"], "true")
        self.assertNotIn("minPrice", params)

    def test_v1_number_response_is_parsed(self):
        provider = SmsActivateProvider(api_key="k")
        with mock.patch.object(
            provider, "_request", return_value=_Resp("ACCESS_NUMBER:9001:66123456789")
        ):
            info = provider._request_number("getNumber", "dr", "52")
        self.assertEqual(info["activationId"], "9001")
        self.assertEqual(info["phoneNumber"], "66123456789")

    def test_get_number_walks_candidate_countries(self):
        provider = SmsActivateProvider(api_key="k", reuse_phone_to_max=False)
        calls = []

        def fake_request(action, service, country):
            calls.append((action, country))
            if country != "52":
                raise RuntimeError("NO_NUMBERS")
            return {"activationId": "9001", "phoneNumber": "66123", "countryPhoneCode": "66"}

        with mock.patch.object(provider, "_request_number", side_effect=fake_request):
            activation = provider.get_number(service="dr", country_candidates=["16", "52"])

        self.assertEqual(activation.phone_number, "+66123")
        self.assertEqual(activation.country, "52")
        self.assertFalse(activation.metadata["reused"])
        # 每个国家先试 V2 再退 V1
        self.assertEqual(calls[:2], [("getNumberV2", "16"), ("getNumber", "16")])

    def test_get_number_reports_every_candidate_failure(self):
        provider = SmsActivateProvider(api_key="k", reuse_phone_to_max=False)
        with mock.patch.object(provider, "_request_number", side_effect=RuntimeError("NO_BALANCE")):
            with self.assertRaises(RuntimeError) as ctx:
                provider.get_number(service="dr", country_candidates=["16", "52"])

        message = str(ctx.exception)
        self.assertIn("16:", message)
        self.assertIn("52:", message)

    def test_number_is_reused_until_success_cap(self):
        provider = SmsActivateProvider(api_key="k", reuse_phone_to_max=True, phone_success_max=2)
        info = {"activationId": "9001", "phoneNumber": "66123", "countryPhoneCode": "66"}

        with mock.patch.object(provider, "_request_number", return_value=info) as rent:
            first = provider.get_number(service="dr", country_candidates=["52"])
            second = provider.get_number(service="dr", country_candidates=["52"])

        self.assertEqual(rent.call_count, 1)
        self.assertFalse(first.metadata["reused"])
        self.assertTrue(second.metadata["reused"])
        self.assertTrue(self.cache_path.exists())

    def test_reuse_stops_after_success_cap(self):
        provider = SmsActivateProvider(api_key="k", reuse_phone_to_max=True, phone_success_max=1)
        info = {"activationId": "9001", "phoneNumber": "66123", "countryPhoneCode": "66"}

        with mock.patch.object(provider, "_request_number", return_value=info), \
                mock.patch.object(provider, "_request", return_value=_Resp("ACCESS_ACTIVATION")):
            provider.get_number(service="dr", country_candidates=["52"])
            provider.report_success("9001")
            reuse = provider._load_cache("dr", "52")

        self.assertIsNone(reuse)

    def test_rejected_number_stops_reuse_and_refunds(self):
        provider = SmsActivateProvider(api_key="k", reuse_phone_to_max=True)
        info = {"activationId": "9001", "phoneNumber": "66123", "countryPhoneCode": "66"}

        with mock.patch.object(provider, "_request_number", return_value=info), \
                mock.patch.object(provider, "_request", return_value=_Resp("ACCESS_CANCEL")) as req:
            provider.get_number(service="dr", country_candidates=["52"])
            provider.mark_send_failed("9001", reason="phone_number_already_in_use")

        self.assertEqual(req.call_args.args[0]["status"], 8)
        self.assertIsNone(sms_service._SMS_CACHE)

    def test_status_v2_extracts_code_from_channel_payload(self):
        provider = SmsActivateProvider(api_key="k")
        with mock.patch.object(
            provider, "_request", return_value=_Resp(payload={"sms": {"code": "654321"}})
        ):
            result = provider.get_status_v2("9001")
        self.assertEqual(result["code"], "654321")

    def test_status_v2_falls_back_to_plain_text(self):
        provider = SmsActivateProvider(api_key="k")
        with mock.patch.object(provider, "_request", return_value=_Resp("STATUS_OK:111222")):
            self.assertEqual(provider.get_status_v2("9001")["code"], "111222")

    def test_wait_for_code_returns_first_fresh_code(self):
        provider = SmsActivateProvider(api_key="k")
        with mock.patch.object(
            provider, "get_status_v2", return_value={"status": "ok", "code": "246813"}
        ):
            result = provider.wait_for_code("9001", timeout=5)
        self.assertEqual(result["code"], "246813")

    def test_wait_for_code_stops_on_cancel(self):
        provider = SmsActivateProvider(api_key="k")
        with mock.patch.object(provider, "get_status_v2", return_value={"status": "cancel"}):
            self.assertIsNone(provider.wait_for_code("9001", timeout=5))


class ProviderFactoryTests(unittest.TestCase):
    def test_unknown_provider_is_rejected(self):
        with self.assertRaises(RuntimeError):
            create_sms_provider("nope", {"sms_api_key": "k"})

    def test_missing_api_key_is_rejected(self):
        with self.assertRaises(RuntimeError):
            create_sms_provider("smsbower", {})

    def test_provider_key_normalisation_and_defaults(self):
        provider = create_sms_provider("Hero_SMS", {"sms_api_key": "k"})
        self.assertIn("hero-sms.com", provider.base_url)
        self.assertEqual(provider.default_service, SMS_DEFAULT_SERVICE)
        self.assertEqual(provider.default_country, SMS_DEFAULT_COUNTRY)
        self.assertFalse(provider.reuse_phone_to_max)

    def test_config_values_are_applied(self):
        provider = create_sms_provider(
            "smsbower",
            {
                "sms_api_key": "k",
                "sms_service": "go",
                "sms_country": "16",
                "sms_max_price": "0.8",
                "sms_reuse_phone": True,
                "sms_phone_success_max": "5",
                "sms_proxy": "http://proxy:1",
            },
        )
        self.assertEqual(provider.default_service, "go")
        self.assertEqual(provider.default_country, "16")
        self.assertEqual(provider.max_price, 0.8)
        self.assertTrue(provider.reuse_phone_to_max)
        self.assertEqual(provider.phone_success_max, 5)
        self.assertEqual(provider._proxies["https"], "http://proxy:1")


class SettingsResolutionTests(unittest.TestCase):
    def test_task_overrides_win_over_global_settings(self):
        with mock.patch(
            "core.config_store.config_store.get_all",
            return_value={"sms_country": "52", "sms_api_key": "global", "proxy": "p"},
        ):
            settings = resolve_sms_settings({"sms_country": "16", "sms_api_key": "", "other": 1})

        self.assertEqual(settings["sms_country"], "16")
        self.assertEqual(settings["sms_api_key"], "global")
        self.assertNotIn("proxy", settings)
        self.assertNotIn("other", settings)


class PhoneCallbackBuilderTests(unittest.TestCase):
    def test_disabled_returns_no_controller(self):
        self.assertIsNone(build_phone_callback({"sms_enabled": False, "sms_api_key": "k"}))

    def test_enabled_without_api_key_returns_no_controller(self):
        self.assertIsNone(build_phone_callback({"sms_enabled": True}))

    def test_controller_inherits_task_proxy_and_defaults(self):
        controller = build_phone_callback(
            {"sms_enabled": True, "sms_api_key": "k"}, proxy="http://proxy:1"
        )
        self.assertIsNotNone(controller)
        self.assertEqual(controller.provider_key, "smsbower")
        self.assertEqual(controller.service, SMS_DEFAULT_SERVICE)
        self.assertEqual(controller.country, SMS_DEFAULT_COUNTRY)
        self.assertEqual(controller.config["sms_proxy"], "http://proxy:1")
        self.assertFalse(controller.auto_select_country)

    def test_explicit_sms_proxy_is_not_overwritten(self):
        controller = build_phone_callback(
            {"sms_enabled": True, "sms_api_key": "k", "sms_proxy": "http://own:2"},
            proxy="http://proxy:1",
        )
        self.assertEqual(controller.config["sms_proxy"], "http://own:2")


class PhoneCallbackControllerTests(unittest.TestCase):
    def _controller(self, config=None, **kwargs):
        base = {"sms_api_key": "k"}
        base.update(config or {})
        self.logs = []
        return PhoneCallbackController(
            "smsbower", base, log_fn=self.logs.append, **kwargs
        )

    def test_manual_country_is_used_verbatim(self):
        controller = self._controller(country="16")
        provider = mock.Mock(spec=SmsActivateProvider)
        self.assertEqual(controller._resolve_country_candidates(provider), ["16"])

    def test_auto_selection_ranks_the_allowed_countries(self):
        controller = self._controller(
            {"sms_allowed_countries": "16, 52 ;62"}, auto_select_country=True
        )
        provider = mock.Mock(spec=SmsActivateProvider)
        provider.get_top_countries.return_value = [
            {"country": "62", "price": 0.1},
            {"country": "16", "price": 0.4},
        ]

        candidates = controller._resolve_country_candidates(provider)

        # 排名内的按价格升序在前，排名外的保留原顺序垫底
        self.assertEqual(candidates, ["62", "16", "52"])

    def test_auto_selection_survives_ranking_failure(self):
        controller = self._controller(
            {"sms_allowed_countries": "16,52"}, auto_select_country=True
        )
        provider = mock.Mock(spec=SmsActivateProvider)
        provider.get_top_countries.side_effect = RuntimeError("排名接口挂了")

        self.assertEqual(controller._resolve_country_candidates(provider), ["16", "52"])

    def test_auto_selection_without_allow_list_uses_best_country(self):
        controller = self._controller(
            {"sms_auto_min_stock": "50", "sms_auto_max_price": "1.0"},
            auto_select_country=True,
        )
        provider = mock.Mock(spec=SmsActivateProvider)
        provider.get_best_country.return_value = "52"

        self.assertEqual(controller._resolve_country_candidates(provider), ["52"])
        self.assertEqual(provider.get_best_country.call_args.kwargs["min_stock"], 50)
        self.assertEqual(provider.get_best_country.call_args.kwargs["max_price"], 1.0)

    def test_auto_selection_falls_back_to_default_country(self):
        controller = self._controller(auto_select_country=True, country="16")
        provider = mock.Mock(spec=SmsActivateProvider)
        provider.get_best_country.return_value = ""

        self.assertEqual(controller._resolve_country_candidates(provider), ["16"])

    def test_off_whitelist_country_is_called_out_once(self):
        """尼日利亚这类号段 OpenAI 会改走 WhatsApp，日志里得说清楚。"""
        controller = self._controller(country="19")
        provider = mock.Mock(spec=SmsActivateProvider)
        provider.get_number.side_effect = [
            SmsActivation(activation_id="1", phone_number="+2349160938262", country="19"),
            SmsActivation(activation_id="2", phone_number="+2349116600547", country="19"),
        ]
        controller.provider = provider

        controller.get_phone()
        controller.get_phone()

        hints = [line for line in self.logs if "白名单" in line]
        self.assertEqual(len(hints), 1)
        self.assertIn("尼日利亚", hints[0])
        self.assertIn("泰国", hints[0])

    def test_whitelisted_country_gets_no_hint(self):
        controller = self._controller(country="52")
        provider = mock.Mock(spec=SmsActivateProvider)
        provider.get_number.return_value = SmsActivation(
            activation_id="1", phone_number="+66123", country="52"
        )
        controller.provider = provider

        controller.get_phone()

        self.assertEqual([line for line in self.logs if "白名单" in line], [])

    def test_get_phone_then_code_then_success(self):
        controller = self._controller(country="52")
        provider = mock.Mock(spec=SmsActivateProvider)
        provider.auto_report_success_on_code = False
        provider.get_number.return_value = SmsActivation(
            activation_id="9001", phone_number="+66123", country="52"
        )
        provider.get_code.return_value = "135790"
        controller.provider = provider

        self.assertEqual(controller.get_phone(), "+66123")
        self.assertEqual(controller.get_code(timeout=30), "135790")
        self.assertFalse(controller.completed)

        controller.report_success()
        provider.report_success.assert_called_once_with("9001")
        self.assertTrue(controller.completed)

    def test_code_auto_reports_success_when_provider_asks_for_it(self):
        controller = self._controller(country="52")
        provider = mock.Mock(spec=SmsActivateProvider)
        provider.auto_report_success_on_code = True
        provider.get_number.return_value = SmsActivation(
            activation_id="9001", phone_number="+66123"
        )
        provider.get_code.return_value = "135790"
        controller.provider = provider

        controller.get_phone()
        controller.get_code()

        self.assertTrue(controller.completed)

    def test_get_code_requires_a_rented_number(self):
        controller = self._controller()
        with self.assertRaises(RuntimeError):
            controller.get_code()

    def test_cleanup_releases_unused_number(self):
        controller = self._controller(country="52")
        provider = mock.Mock(spec=SmsActivateProvider)
        provider.get_number.return_value = SmsActivation(
            activation_id="9001", phone_number="+66123"
        )
        controller.provider = provider
        controller.get_phone()

        controller.cleanup()

        provider.cancel.assert_called_once_with("9001")
        self.assertIsNone(controller.activation)

    def test_cleanup_keeps_a_completed_number(self):
        controller = self._controller(country="52")
        provider = mock.Mock(spec=SmsActivateProvider)
        provider.get_number.return_value = SmsActivation(
            activation_id="9001", phone_number="+66123"
        )
        controller.provider = provider
        controller.get_phone()
        controller.report_success()

        controller.cleanup()

        provider.cancel.assert_not_called()

    def test_rent_failure_releases_the_reuse_lock(self):
        controller = self._controller(country="52")
        provider = mock.Mock(spec=SmsActivateProvider)
        provider.get_number.side_effect = RuntimeError("NO_NUMBERS")
        controller.provider = provider

        with self.assertRaises(RuntimeError):
            controller.get_phone()

        self.assertFalse(controller._verify_lock_acquired)
        # 锁没泄漏，下一次租号才能继续
        self.assertTrue(sms_service._SMS_VERIFY_LOCK.acquire(blocking=False))
        sms_service._SMS_VERIFY_LOCK.release()


class CachePersistenceTests(_IsolatedCacheMixin, unittest.TestCase):
    def test_cache_file_stores_used_codes_as_sorted_list(self):
        provider = SmsActivateProvider(api_key="k")
        provider._save_cache(
            {
                **provider._cache_identity("dr", "52"),
                "activation_id": "9001",
                "used_codes": {"222", "111"},
            }
        )
        saved = json.loads(self.cache_path.read_text(encoding="utf-8"))
        self.assertEqual(saved["used_codes"], ["111", "222"])

    def test_cache_from_another_api_key_is_ignored(self):
        SmsActivateProvider(api_key="k1")._save_cache(
            {
                **SmsActivateProvider(api_key="k1")._cache_identity("dr", "52"),
                "activation_id": "9001",
                "acquired_at": 1e12,
            }
        )
        sms_service._SMS_CACHE = None
        self.assertIsNone(SmsActivateProvider(api_key="k2")._load_cache("dr", "52"))

    def test_expired_cache_is_dropped(self):
        provider = SmsActivateProvider(api_key="k")
        provider._save_cache(
            {
                **provider._cache_identity("dr", "52"),
                "activation_id": "9001",
                "acquired_at": 0,
            }
        )
        self.assertIsNone(provider._load_cache("dr", "52"))
        self.assertFalse(self.cache_path.exists())


if __name__ == "__main__":
    unittest.main()
