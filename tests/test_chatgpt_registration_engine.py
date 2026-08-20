import unittest
from pathlib import Path
from unittest import mock

from core.base_mailbox import MailboxAccount
from platforms.chatgpt.protocol.mailbox_adapter import MailboxProviderAdapter
from platforms.chatgpt.registration_engine import (
    REGISTRATION_MODE_ACCESS_TOKEN_ONLY,
    REGISTRATION_MODE_REFRESH_TOKEN,
    ChatGPTRegistrationEngine,
    RegistrationResult,
    generate_password,
)


class _StubMailbox:
    def __init__(self, email="demo@example.com", ids=None, code="123456"):
        self.account = MailboxAccount(email=email, account_id="stub")
        self._ids = ids
        self._code = code
        self.wait_calls = []

    def get_email(self):
        return self.account

    def get_current_ids(self, account):
        if self._ids is None:
            raise RuntimeError("列举邮件失败")
        return self._ids

    def wait_for_code(self, account, **kwargs):
        self.wait_calls.append((account, kwargs))
        return self._code


def _auth_result(**overrides):
    fields = dict(
        email="demo@example.com",
        password="pw",
        access_token="",
        refresh_token="",
        id_token="",
        session_token="",
        cookie_header="",
        device_id="dev-1",
        totp_secret="",
    )
    fields.update(overrides)
    return mock.Mock(**fields)


class MailboxProviderAdapterTests(unittest.TestCase):
    def test_create_mailbox_records_baseline_ids(self):
        mailbox = _StubMailbox(ids={"mid-1"})
        adapter = MailboxProviderAdapter(mailbox)

        self.assertEqual(adapter.create_mailbox(), "demo@example.com")
        self.assertEqual(adapter._before_ids, {"mid-1"})

    def test_create_mailbox_tolerates_baseline_failure(self):
        adapter = MailboxProviderAdapter(_StubMailbox(ids=None))

        self.assertEqual(adapter.create_mailbox(), "demo@example.com")
        self.assertEqual(adapter._before_ids, set())

    def test_create_mailbox_rejects_blank_address(self):
        adapter = MailboxProviderAdapter(_StubMailbox(email=""), kind="tempmail_lol")

        with self.assertRaises(RuntimeError) as ctx:
            adapter.create_mailbox()

        self.assertIn("tempmail_lol", str(ctx.exception))

    def test_fixed_email_wins_over_mailbox_address(self):
        adapter = MailboxProviderAdapter(
            _StubMailbox(email="pool@example.com", ids=set()),
            fixed_email="fixed@example.com",
        )
        self.assertEqual(adapter.create_mailbox(), "fixed@example.com")

    def test_wait_for_otp_forwards_dedup_window(self):
        mailbox = _StubMailbox(ids={"mid-1"})
        adapter = MailboxProviderAdapter(mailbox)
        adapter.create_mailbox()

        code = adapter.wait_for_otp("demo@example.com", timeout=45, issued_after=1234.5)

        self.assertEqual(code, "123456")
        _, kwargs = mailbox.wait_calls[0]
        self.assertEqual(kwargs["before_ids"], {"mid-1"})
        self.assertEqual(kwargs["otp_sent_at"], 1234.5)
        self.assertEqual(kwargs["timeout"], 45)

    def test_configured_timeout_overrides_protocol_request(self):
        mailbox = _StubMailbox(ids=set())
        adapter = MailboxProviderAdapter(mailbox, otp_timeout=200)
        adapter.create_mailbox()
        adapter.wait_for_otp("demo@example.com", timeout=45)

        _, kwargs = mailbox.wait_calls[0]
        self.assertEqual(kwargs["timeout"], 200)

    def test_wait_for_otp_requires_created_mailbox(self):
        adapter = MailboxProviderAdapter(_StubMailbox())
        with self.assertRaises(RuntimeError):
            adapter.wait_for_otp("demo@example.com")

    def test_empty_code_raises_timeout(self):
        adapter = MailboxProviderAdapter(_StubMailbox(ids=set(), code=""))
        adapter.create_mailbox()
        with self.assertRaises(TimeoutError):
            adapter.wait_for_otp("demo@example.com")


class RegistrationEngineConfigTests(unittest.TestCase):
    def _engine(self, **overrides):
        kwargs = dict(mailbox=_StubMailbox(ids=set()), email="demo@example.com")
        kwargs.update(overrides)
        return ChatGPTRegistrationEngine(**kwargs)

    def test_generated_password_is_non_trivial(self):
        password = generate_password()
        self.assertEqual(len(password), 16)
        self.assertNotEqual(password, generate_password())

    def test_default_overrides_allow_login_and_carry_otp_timeout(self):
        overrides = self._engine()._env_overrides()

        self.assertEqual(overrides["WEBUI_ALLOW_LOGIN"], "1")
        self.assertEqual(overrides["OTP_TIMEOUT"], "180")
        self.assertNotIn("OAUTH_CODEX_RT_EXCHANGE", overrides)

    def test_access_token_only_mode_skips_codex_oauth(self):
        overrides = self._engine(mode=REGISTRATION_MODE_ACCESS_TOKEN_ONLY)._env_overrides()

        self.assertEqual(overrides["OAUTH_CODEX_RT_EXCHANGE"], "0")
        self.assertEqual(overrides["OAUTH_CODEX_RT_BEFORE_CALLBACK"], "0")

    def test_sms_config_is_translated_to_protocol_switches(self):
        overrides = self._engine(
            extra_config={
                "sms_per_phone_timeout": 120,
                "sms_max_phone_attempts": 5,
                "sms_code_retries_per_phone": 4,
                "chatgpt_phone_number": "+66123456789",
            }
        )._env_overrides()

        self.assertEqual(overrides["OPENAI_PHONE_OTP_TIMEOUT"], "120")
        self.assertEqual(overrides["OPENAI_PHONE_MAX_ATTEMPTS"], "5")
        self.assertEqual(overrides["OPENAI_PHONE_OTP_CODE_RETRIES"], "4")
        self.assertEqual(overrides["OPENAI_PHONE_NUMBER"], "+66123456789")

    def test_blank_sms_config_is_not_forwarded(self):
        overrides = self._engine(
            extra_config={"sms_per_phone_timeout": "", "chatgpt_phone_number": None}
        )._env_overrides()

        self.assertNotIn("OPENAI_PHONE_OTP_TIMEOUT", overrides)
        self.assertNotIn("OPENAI_PHONE_NUMBER", overrides)

    def test_otp_timeout_prefers_first_valid_config_key(self):
        self.assertEqual(
            self._engine(extra_config={"mailbox_otp_timeout_seconds": 90})._otp_timeout(), 90
        )
        self.assertEqual(
            self._engine(
                extra_config={"mailbox_otp_timeout_seconds": "abc", "otp_timeout": 240}
            )._otp_timeout(),
            240,
        )
        self.assertEqual(self._engine(extra_config={"otp_timeout": -1})._otp_timeout(), 180)

    def test_on_password_callback_records_credentials(self):
        logs = []
        engine = self._engine(log_fn=logs.append)

        engine._on_password("demo@example.com", "生效密码")

        self.assertEqual(engine.password, "生效密码")
        self.assertTrue(any("生效密码" in line for line in logs))

    def test_sms_callback_is_none_when_disabled(self):
        engine = self._engine(extra_config={"sms_enabled": False})
        with mock.patch(
            "platforms.chatgpt.registration_engine.resolve_sms_settings",
            return_value={"sms_enabled": False},
        ):
            self.assertIsNone(engine._build_sms_callback())

    def test_sms_callback_is_wired_when_enabled(self):
        logs = []
        engine = self._engine(log_fn=logs.append, proxy="http://proxy:1")
        controller = mock.Mock(provider_key="smsbower")

        with mock.patch(
            "platforms.chatgpt.registration_engine.resolve_sms_settings",
            return_value={"sms_enabled": True, "sms_api_key": "k"},
        ), mock.patch(
            "platforms.chatgpt.registration_engine.build_phone_callback",
            return_value=controller,
        ) as build:
            self.assertIs(engine._build_sms_callback(), controller)

        self.assertEqual(build.call_args.kwargs["proxy"], "http://proxy:1")
        self.assertTrue(any("smsbower" in line for line in logs))


class RegistrationEngineRunTests(unittest.TestCase):
    def _run_with_flow(self, flow, **engine_kwargs):
        kwargs = dict(mailbox=_StubMailbox(ids=set()), email="demo@example.com")
        kwargs.update(engine_kwargs)
        engine = ChatGPTRegistrationEngine(**kwargs)
        with mock.patch(
            "platforms.chatgpt.registration_engine.AuthFlow", return_value=flow
        ), mock.patch(
            "platforms.chatgpt.registration_engine.resolve_sms_settings", return_value={}
        ):
            return engine, engine.run()

    def test_successful_run_maps_protocol_result(self):
        flow = mock.Mock()
        flow.run_register.return_value = _auth_result(
            access_token="at", refresh_token="rt", session_token="st", cookie_header="c=1"
        )

        _, result = self._run_with_flow(flow)

        self.assertTrue(result.success)
        self.assertEqual(result.access_token, "at")
        self.assertEqual(result.refresh_token, "rt")
        self.assertEqual(result.session_token, "st")
        self.assertEqual(result.cookie_header, "c=1")
        self.assertEqual(result.metadata["device_id"], "dev-1")
        # 协议层拿到的是适配后的邮箱 provider，而不是裸 mailbox
        provider = flow.run_register.call_args.args[0]
        self.assertIsInstance(provider, MailboxProviderAdapter)

    def test_failure_without_credentials_is_reported_as_error(self):
        flow = mock.Mock()
        flow.run_register.side_effect = RuntimeError("OTP 超时")
        flow.result = _auth_result(password="已生效密码")

        _, result = self._run_with_flow(flow)

        self.assertFalse(result.success)
        self.assertIn("OTP 超时", result.error_message)
        self.assertEqual(result.password, "已生效密码")

    def test_late_failure_with_credentials_is_salvaged_as_partial(self):
        logs = []
        flow = mock.Mock()
        flow.run_register.side_effect = RuntimeError("Codex OAuth 交换失败")
        flow.result = _auth_result(access_token="at", session_token="st")

        _, result = self._run_with_flow(
            flow, mode=REGISTRATION_MODE_REFRESH_TOKEN, log_fn=logs.append
        )

        self.assertTrue(result.success)
        self.assertTrue(result.metadata["partial"])
        self.assertIn("Codex OAuth 交换失败", result.metadata["last_error"])
        self.assertTrue(any("缺 refresh_token" in line for line in logs))

    def test_access_token_only_salvage_is_not_partial(self):
        flow = mock.Mock()
        flow.run_register.side_effect = RuntimeError("收尾异常")
        flow.result = _auth_result(access_token="at")

        _, result = self._run_with_flow(flow, mode=REGISTRATION_MODE_ACCESS_TOKEN_ONLY)

        self.assertTrue(result.success)
        self.assertFalse(result.metadata["partial"])


class SentinelNodeRuntimeTests(unittest.TestCase):
    def test_missing_node_reports_the_real_cause(self):
        from platforms.chatgpt.protocol import sentinel_quickjs

        with mock.patch.dict(
            "os.environ", {"OPENAI_SENTINEL_NODE_PATH": "/nonexistent/node"}
        ):
            with self.assertRaises(RuntimeError) as ctx:
                sentinel_quickjs._run_quickjs_action(
                    action="requirements",
                    sdk_file=Path("/tmp/sdk.js"),
                    quickjs_script=sentinel_quickjs._quickjs_script_path(),
                    payload={},
                    timeout_ms=1000,
                )

        message = str(ctx.exception)
        self.assertIn("/nonexistent/node", message)
        self.assertIn("OPENAI_SENTINEL_NODE_PATH", message)


class RegistrationResultTests(unittest.TestCase):
    def test_defaults_are_empty_strings(self):
        result = RegistrationResult(success=False)
        self.assertEqual(result.email, "")
        self.assertEqual(result.source, "register")
        self.assertEqual(result.metadata, {})


if __name__ == "__main__":
    unittest.main()
