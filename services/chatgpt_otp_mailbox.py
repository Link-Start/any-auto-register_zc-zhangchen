"""给一个【已知地址】找回收件通道。

注册时邮箱是从池子里现领的，链路信息还在手上；补 RT 面对的是库里的老号，只有
一个地址，得反查它当初是哪来的。按可靠性从高到低找：

    1. iCloud 隐私邮箱表里有这个地址 → 走主号 IMAP 按收件人过滤
    2. 微软邮箱池里还留着这个号 → 用池里的 OAuth/IMAP 凭据收信
    3. 地址域名对得上当前配置的邮箱服务 → 用该服务的管理接口按地址收信
    4. 都不是 → 返回 None，由调用方决定是硬着头皮试还是直接放弃

三条路都可能失败（主号掉线、号已从池里弹出、临时邮箱早过期），所以返回值一律
是 ``(provider, reason)``：provider 为 None 时 reason 说明为什么读不到。
"""

from __future__ import annotations

import logging
import time
from typing import Callable, Optional

from platforms.chatgpt.protocol import MailProvider, extract_otp

logger = logging.getLogger(__name__)

# 按地址收信时的轮询间隔，和邮箱池实现里的节奏保持一致
POLL_INTERVAL_SECONDS = 5.0
ICLOUD_FETCH_LIMIT = 20


class ICloudAliasMailProvider(MailProvider):
    """通过 iCloud 主号 IMAP 读隐私邮箱收到的验证码。"""

    kind = "icloud_alias"
    display_name = "iCloud 隐私邮箱"
    accepts_existing_account = True

    def __init__(
        self,
        alias_id: int,
        address: str,
        *,
        fetch: Optional[Callable[[], list]] = None,
        poll_interval: float = POLL_INTERVAL_SECONDS,
        log_fn: Optional[Callable[[str], None]] = None,
    ):
        self._alias_id = int(alias_id)
        self._address = address
        self._fetch = fetch or self._fetch_messages
        self._poll_interval = max(float(poll_interval), 0.5)
        self._log = log_fn or logger.info
        self._seen: set[str] = set()

    def create_mailbox(self) -> str:
        return self._address

    def prime(self) -> None:
        """记下现有邮件，免得把上一轮的旧码当成本轮的。"""
        try:
            self._seen = {self._message_id(item) for item in self._fetch()}
        except Exception as exc:
            logger.debug("iCloud 隐私邮箱 %s 基线读取失败: %s", self._address, exc)

    def wait_for_otp(
        self,
        email_addr: str,
        timeout: int = 120,
        issued_after: Optional[float] = None,
    ) -> str:
        deadline = time.monotonic() + max(int(timeout or 0), 1)
        # Apple 转发有延迟，时间窗放宽 30 秒，否则常把唯一那封码信判成旧信
        cutoff = (issued_after - 30) if issued_after else None

        while True:
            try:
                messages = self._fetch()
            except Exception as exc:
                self._log(f"[补RT] 读 iCloud 隐私邮箱失败: {exc}")
                messages = []

            for item in messages:
                message_id = self._message_id(item)
                if message_id in self._seen:
                    continue
                self._seen.add(message_id)
                if cutoff and self._received_at(item) and self._received_at(item) < cutoff:
                    continue
                code = extract_otp(self._searchable_text(item))
                if code:
                    return code

            if time.monotonic() >= deadline:
                raise TimeoutError(f"iCloud 隐私邮箱 {self._address} 未收到验证码")
            time.sleep(self._poll_interval)

    def _fetch_messages(self) -> list:
        from services.icloud_service import fetch_alias_messages

        return fetch_alias_messages(self._alias_id, limit=ICLOUD_FETCH_LIMIT)

    @staticmethod
    def _message_id(item) -> str:
        return str(getattr(item, "provider_message_id", "") or id(item))

    @staticmethod
    def _received_at(item) -> Optional[float]:
        received = getattr(item, "received_at", None)
        if received is None:
            return None
        try:
            return received.timestamp()
        except Exception:
            return None

    @staticmethod
    def _searchable_text(item) -> str:
        parts = [
            str(getattr(item, "subject", "") or ""),
            str(getattr(item, "text_body", "") or ""),
            str(getattr(item, "html_body", "") or ""),
            str(getattr(item, "snippet", "") or ""),
        ]
        return "\n".join(part for part in parts if part)


def resolve_otp_mail_provider(
    email: str,
    *,
    account_extra: Optional[dict] = None,
    config: Optional[dict] = None,
    proxy: Optional[str] = None,
    otp_timeout: Optional[int] = None,
    log_fn: Optional[Callable[[str], None]] = None,
) -> tuple[Optional[MailProvider], str]:
    """给已注册账号的邮箱地址找一个能收验证码的 provider。"""
    address = (email or "").strip()
    if not address:
        return None, "账号没有邮箱地址"

    account_extra = dict(account_extra or {})
    config = dict(config or {})
    reasons: list[str] = []

    for builder in (_build_icloud_provider, _build_outlook_provider, _build_configured_provider):
        try:
            provider, reason = builder(
                address,
                account_extra=account_extra,
                config=config,
                proxy=proxy,
                otp_timeout=otp_timeout,
                log_fn=log_fn,
            )
        except Exception as exc:
            reasons.append(str(exc))
            continue
        if provider is not None:
            _prime(provider)
            return provider, ""
        if reason:
            reasons.append(reason)

    return None, "；".join(reasons) or "没有匹配的收件通道"


def _prime(provider: MailProvider) -> None:
    prime = getattr(provider, "prime", None)
    if callable(prime):
        try:
            prime()
        except Exception as exc:
            logger.debug("邮箱基线读取失败: %s", exc)


def _build_icloud_provider(address: str, *, log_fn=None, **_kwargs):
    from sqlmodel import Session, select

    from core.db import ICloudAliasModel, engine

    with Session(engine) as session:
        alias = session.exec(
            select(ICloudAliasModel).where(ICloudAliasModel.address == address)
        ).first()
        alias_id = alias.id if alias else None

    if alias_id is None:
        return None, ""
    return ICloudAliasMailProvider(alias_id, address, log_fn=log_fn), ""


def _build_outlook_provider(address: str, *, config: dict, proxy=None, otp_timeout=None, **_kwargs):
    from sqlmodel import Session, select

    from core.base_mailbox import MailboxAccount, create_mailbox
    from core.db import OutlookAccountModel, engine
    from platforms.chatgpt.protocol.mailbox_adapter import FixedAddressProviderAdapter

    with Session(engine) as session:
        row = session.exec(
            select(OutlookAccountModel).where(OutlookAccountModel.email == address)
        ).first()
        if row is None:
            return None, ""
        credentials = {
            "provider": "microsoft",
            "password": row.password or "",
            "client_id": row.client_id or "",
            "refresh_token": row.refresh_token or "",
            "account_type": row.account_type or "microsoft_oauth",
            "mailapi_url": row.mailapi_url or "",
        }
        account_id = str(row.id or "")

    mailbox = create_mailbox("outlook", extra=config, proxy=proxy)
    account = MailboxAccount(email=address, account_id=account_id, extra=credentials)
    return (
        FixedAddressProviderAdapter(mailbox, account, kind="微软邮箱", otp_timeout=otp_timeout),
        "",
    )


def _build_configured_provider(
    address: str, *, account_extra: dict, config: dict, proxy=None, otp_timeout=None, **_kwargs
):
    from core.base_mailbox import MailboxAccount, create_mailbox
    from platforms.chatgpt.protocol.mailbox_adapter import FixedAddressProviderAdapter

    provider_key = str(
        account_extra.get("mail_provider") or config.get("mail_provider") or ""
    ).strip()
    if not provider_key:
        return None, "没有配置邮箱服务"

    domains = _configured_domains(provider_key, account_extra, config)
    if domains and not _domain_matches(address, domains):
        return None, f"{address} 的域名不属于当前邮箱服务（{provider_key}）"

    merged = dict(config)
    merged.update({k: v for k, v in account_extra.items() if v not in (None, "")})
    mailbox = create_mailbox(provider_key, extra=merged, proxy=proxy)
    account = MailboxAccount(
        email=address,
        account_id=str(account_extra.get("mailbox_token") or ""),
        extra=dict(account_extra),
    )
    return (
        FixedAddressProviderAdapter(mailbox, account, kind=provider_key, otp_timeout=otp_timeout),
        "",
    )


def _configured_domains(provider_key: str, account_extra: dict, config: dict) -> list[str]:
    """收集当前邮箱服务已知的域名，用来判断这个地址是不是它发出去的。"""
    keys = (
        f"{provider_key}_domain",
        f"{provider_key}_domains",
        f"{provider_key}_enabled_domains",
        f"{provider_key}_domain_override",
    )
    domains: list[str] = []
    for source in (account_extra, config):
        for key in keys:
            raw = str(source.get(key) or "").strip()
            for item in raw.replace(";", ",").replace(" ", ",").split(","):
                domain = item.strip().lower().lstrip("@")
                if domain and domain not in domains:
                    domains.append(domain)
    return domains


def _domain_matches(address: str, domains: list[str]) -> bool:
    host = address.rsplit("@", 1)[-1].strip().lower()
    if not host:
        return False
    # 子域名邮箱（a.b.example.com）也算 example.com 这个服务发出来的
    return any(host == domain or host.endswith(f".{domain}") for domain in domains)
