"""ChatGPT 注册引擎。

驱动 ``platforms.chatgpt.protocol`` 里的 authorize 状态机跑完整条注册链，把
本仓库的邮箱池、接码配置、任务日志接到协议层的三个注入点上：

    mail_provider   邮箱适配器，负责要地址、等 6 位邮件验证码
    sms_callback    接码控制器，命中 add-phone 时自动租号收短信
    on_password     密码一在 OpenAI 侧生效就回调，避免中途失败把号跑丢

协议层不认识本仓库的任何东西（config_store、任务运行时、账号表都不认识），
所有环境相关的开关都通过 ``env_overrides`` 以实例级配置传进去，进程环境变量
一个字节都不动 —— 多个注册任务并发跑时互不污染。
"""

from __future__ import annotations

import logging
import random
import string
from dataclasses import dataclass, field
from typing import Callable, Optional

from core.base_mailbox import BaseMailbox
from platforms.chatgpt.protocol import AuthFlow, AuthResult, Config
from platforms.chatgpt.protocol.mailbox_adapter import MailboxProviderAdapter
from services.sms_service import build_phone_callback, resolve_sms_settings

logger = logging.getLogger(__name__)

REGISTRATION_MODE_REFRESH_TOKEN = "refresh_token"
REGISTRATION_MODE_ACCESS_TOKEN_ONLY = "access_token_only"

_PASSWORD_ALPHABET = string.ascii_letters + string.digits + "!@#$"


@dataclass
class RegistrationResult:
    """注册结果。"""

    success: bool
    email: str = ""
    password: str = ""
    account_id: str = ""
    workspace_id: str = ""
    access_token: str = ""
    refresh_token: str = ""
    id_token: str = ""
    session_token: str = ""
    cookie_header: str = ""
    error_message: str = ""
    source: str = "register"
    metadata: dict = field(default_factory=dict)

    @classmethod
    def from_auth_result(cls, result: AuthResult, *, source: str = "register") -> "RegistrationResult":
        return cls(
            success=True,
            email=result.email,
            password=result.password,
            access_token=result.access_token,
            refresh_token=result.refresh_token,
            id_token=result.id_token,
            session_token=result.session_token,
            cookie_header=result.cookie_header,
            source=source,
            metadata={"device_id": result.device_id, "totp_secret": result.totp_secret},
        )


def generate_password(length: int = 16) -> str:
    return "".join(random.choices(_PASSWORD_ALPHABET, k=length))


class ChatGPTRegistrationEngine:
    """把一个邮箱跑成一个可用的 ChatGPT 账号。"""

    def __init__(
        self,
        *,
        mailbox: BaseMailbox,
        mode: str = REGISTRATION_MODE_REFRESH_TOKEN,
        proxy: Optional[str] = None,
        email: str = "",
        password: str = "",
        extra_config: Optional[dict] = None,
        log_fn: Optional[Callable[[str], None]] = None,
        mailbox_kind: str = "mailbox",
    ):
        self.mailbox = mailbox
        self.mode = mode
        self.proxy = (proxy or "").strip() or None
        self.email = (email or "").strip()
        self.password = (password or "").strip() or generate_password()
        self.extra_config = dict(extra_config or {})
        self.log = log_fn or logger.info
        self.mailbox_kind = mailbox_kind
        self.flow: Optional[AuthFlow] = None

    def run(self) -> RegistrationResult:
        provider = MailboxProviderAdapter(
            self.mailbox,
            kind=self.mailbox_kind,
            fixed_email=self.email,
            pooled=True,
            ephemeral=not self.email,
            otp_timeout=self._otp_timeout(),
        )
        flow = AuthFlow(
            Config(proxy=self.proxy),
            sms_callback=self._build_sms_callback(),
            env_overrides=self._env_overrides(),
            on_password=self._on_password,
        )
        self.flow = flow

        try:
            result = flow.run_register(provider)
        except Exception as exc:
            return self._salvage(flow, exc)

        return RegistrationResult.from_auth_result(result)

    # ── 协议层注入点 ──

    def _on_password(self, email: str, password: str) -> None:
        """密码在 OpenAI 侧一生效就记下来。

        协议层是在 ``POST user/register`` 成功后立刻回调的，此时账号已经在
        OpenAI 那边建好了。后续任何一步失败（最常见的是 OTP 超时），这行日志
        就是这个号唯一的线索 —— 没有它，号既登不进去也找不回来。
        """
        self.password = password
        self.log(f"密码已在 OpenAI 侧生效: {email} / {password}")

    def _build_sms_callback(self):
        settings = resolve_sms_settings(self.extra_config)
        controller = build_phone_callback(
            settings,
            log_fn=lambda message: self.log(f"[接码] {message}"),
            proxy=self.proxy,
        )
        if controller is not None:
            self.log(f"手机接码已启用: {controller.provider_key}")
        return controller

    def _env_overrides(self) -> dict:
        """把本仓库的配置翻译成协议层认识的开关。"""
        overrides: dict[str, str] = {
            "OTP_TIMEOUT": str(self._otp_timeout()),
            # 邮箱池里的地址常被 OpenAI 判成"已有账号"（二手号或 passwordless_signup
            # 流程），默认走 OTP 登录拿凭证而不是直接判失败 —— 单任务场景下 fast-fail
            # 没有意义，外层本来就会换下一个邮箱重试。
            "WEBUI_ALLOW_LOGIN": "1",
        }

        if self.mode == REGISTRATION_MODE_ACCESS_TOKEN_ONLY:
            # 不要 refresh_token 就别跑 Codex OAuth：每次都要多花约 10 秒且必然告警
            overrides["OAUTH_CODEX_RT_EXCHANGE"] = "0"
            overrides["OAUTH_CODEX_RT_BEFORE_CALLBACK"] = "0"

        for config_key, env_key in (
            ("sms_per_phone_timeout", "OPENAI_PHONE_OTP_TIMEOUT"),
            ("sms_max_phone_attempts", "OPENAI_PHONE_MAX_ATTEMPTS"),
            ("sms_code_retries_per_phone", "OPENAI_PHONE_OTP_CODE_RETRIES"),
            ("chatgpt_phone_number", "OPENAI_PHONE_NUMBER"),
        ):
            value = str(self.extra_config.get(config_key) or "").strip()
            if value:
                overrides[env_key] = value

        return overrides

    def _otp_timeout(self) -> int:
        for key in ("mailbox_otp_timeout_seconds", "email_otp_timeout_seconds", "otp_timeout"):
            try:
                seconds = int(str(self.extra_config.get(key) or "").strip())
            except ValueError:
                continue
            if seconds > 0:
                return seconds
        return 180

    # ── 部分成功的抢救 ──

    def _salvage(self, flow: AuthFlow, exc: Exception) -> RegistrationResult:
        """流程末段炸了但凭证已经到手时，别把号一起扔掉。

        典型场景是 Codex OAuth 交换失败：access_token 和 session_token 早就拿到了，
        账号完全可用，只是没有 refresh_token。这种情况按成功处理，把缺什么记在
        metadata 里，比让调用方重跑一遍浪费一个邮箱划算。
        """
        result = flow.result
        has_credentials = bool(result.access_token or result.session_token or result.refresh_token)
        if not has_credentials:
            return RegistrationResult(
                success=False,
                email=result.email or self.email,
                password=result.password or self.password,
                error_message=str(exc),
            )

        needs_refresh_token = self.mode == REGISTRATION_MODE_REFRESH_TOKEN
        partial = needs_refresh_token and not result.refresh_token
        if partial:
            self.log(f"注册末段异常但凭证部分可用（缺 refresh_token）: {exc}")
        else:
            self.log(f"注册末段异常但所需凭证已齐: {exc}")

        salvaged = RegistrationResult.from_auth_result(result)
        salvaged.metadata["partial"] = partial
        salvaged.metadata["last_error"] = str(exc)
        return salvaged
