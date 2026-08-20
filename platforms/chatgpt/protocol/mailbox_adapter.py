"""把本仓库的 ``BaseMailbox`` 接到协议层的 ``MailProvider`` 上。

协议层只认识两个动作：要一个地址、等一个 6 位码。本仓库的邮箱池实现（
``core.base_mailbox``）接口更宽，还带 before_ids 去重、任务暂停 checkpoint、
otp_sent_at 时间窗这些东西，这个适配器负责把两边对齐。

两处必须小心：

``issued_after`` 是协议层的防串号时间窗，OpenAI 一轮流程里会因为 login_hint
抢跑、密码注册后重发等原因发好几封码完全一样的信，时间窗没传下去就会读到上
一轮的旧码然后 401。它对应 ``BaseMailbox.wait_for_code`` 的 ``otp_sent_at``。

``mark_dead`` 只对池化邮箱有意义。本仓库的邮箱由任务运行时统一分配，适配器
自己不销号，只记一个标志位让协议层别再空等 —— 真正的号池状态回写在任务层。
"""

from __future__ import annotations

import logging
from typing import Optional

from core.base_mailbox import BaseMailbox, MailboxAccount
from platforms.chatgpt.protocol.mail_provider import MailProvider

logger = logging.getLogger(__name__)


class MailboxProviderAdapter(MailProvider):
    """用一个 ``BaseMailbox`` 实例履行 ``MailProvider`` 契约。"""

    display_name = "邮箱池"

    def __init__(
        self,
        mailbox: BaseMailbox,
        *,
        kind: str = "mailbox",
        fixed_email: str = "",
        pooled: bool = True,
        ephemeral: bool = False,
        accepts_existing_account: bool = False,
        otp_timeout: Optional[int] = None,
    ):
        self._mailbox = mailbox
        self._fixed_email = (fixed_email or "").strip()
        self._account: Optional[MailboxAccount] = None
        self._before_ids: set = set()
        self._dead = False
        self._otp_timeout = otp_timeout
        self.kind = kind
        self.pooled = pooled
        self.ephemeral = ephemeral
        self.accepts_existing_account = accepts_existing_account

    @property
    def account(self) -> Optional[MailboxAccount]:
        return self._account

    def create_mailbox(self) -> str:
        account = self._mailbox.get_email()
        self._account = account

        get_current_ids = getattr(self._mailbox, "get_current_ids", None)
        if callable(get_current_ids):
            try:
                self._before_ids = set(get_current_ids(account) or [])
            except Exception as exc:
                logger.debug("读取邮箱已有邮件 id 失败，按空集合处理: %s", exc)
                self._before_ids = set()
        else:
            self._before_ids = set()

        address = self._fixed_email or str(getattr(account, "email", "") or "").strip()
        if not address:
            raise RuntimeError(f"{self.kind} 未返回可用邮箱地址")
        return address

    def wait_for_otp(
        self,
        email_addr: str,
        timeout: int = 120,
        issued_after: Optional[float] = None,
    ) -> str:
        if self._account is None:
            raise RuntimeError("邮箱尚未创建，无法等待验证码")
        code = self._mailbox.wait_for_code(
            self._account,
            keyword="",
            timeout=self._resolve_timeout(timeout),
            before_ids=self._before_ids,
            otp_sent_at=issued_after,
        )
        if not code:
            raise TimeoutError(f"{self.kind} 未取到验证码")
        return code

    def mark_dead(self, reason: str = "") -> None:
        if not self.pooled:
            return
        self._dead = True
        logger.warning("[%s] 邮箱被协议层判废: %s", self.kind, reason or "未说明原因")

    def _resolve_timeout(self, requested: int) -> int:
        if self._otp_timeout and self._otp_timeout > 0:
            return self._otp_timeout
        return max(int(requested or 0), 1)


class FixedAddressProviderAdapter(MailboxProviderAdapter):
    """绑定到一个【已经存在】的地址，不向邮箱池要新号。

    补 RT、补 2FA 这类后置动作面对的是库里的老号，地址早就定了，走
    ``MailboxProviderAdapter`` 会白白从池子里领一个新邮箱（微软池还会直接把号
    弹出去）。这里直接拿调用方给的 ``MailboxAccount`` 收信。

    ``prime()`` 用来在流程开始前记下收件箱现有邮件 id，避免读到上一轮的旧码；
    只是尽力而为，拿不到就靠 ``issued_after`` 时间窗兜底。
    """

    def __init__(
        self,
        mailbox: BaseMailbox,
        account: MailboxAccount,
        *,
        kind: str = "mailbox",
        otp_timeout: Optional[int] = None,
    ):
        super().__init__(
            mailbox,
            kind=kind,
            fixed_email=str(getattr(account, "email", "") or ""),
            pooled=False,
            ephemeral=False,
            accepts_existing_account=True,
            otp_timeout=otp_timeout,
        )
        self._account = account

    def create_mailbox(self) -> str:
        self.prime()
        if not self._fixed_email:
            raise RuntimeError(f"{self.kind} 缺少邮箱地址")
        return self._fixed_email

    def prime(self) -> None:
        get_current_ids = getattr(self._mailbox, "get_current_ids", None)
        if not callable(get_current_ids):
            return
        try:
            self._before_ids = set(get_current_ids(self._account) or [])
        except Exception as exc:
            logger.debug("[%s] 读取 %s 已有邮件 id 失败: %s", self.kind, self._fixed_email, exc)
            self._before_ids = set()
