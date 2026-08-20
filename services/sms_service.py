"""手机接码服务（sms-activate 协议系）。

供 ChatGPT 注册链路命中 ``add-phone`` 时自动租号、收码、验证。

目前接入 SmsBower 与 HeroSMS，两家共用 sms-activate 的 ``handler_api.php`` 协议，
差别只在 base_url 和固定价格参数的写法上，所以由同一个 provider 类覆盖。

三段式用法（``AuthFlow._handle_add_phone_via_sms`` 就是这么调的）：

    controller = build_phone_callback(config, log_fn=...)
    phone = controller.get_phone()          # 租号
    code = controller.get_code(timeout=80)  # 等短信
    controller.report_success()             # 业务侧验证通过

⚠️ OpenAI 自 2025 年起对大部分国家改用 WhatsApp 验证，纯 SMS 路径实测只有泰国
（country_id=52）稳定可用。其它国家可能抽到 WhatsApp 号导致收不到短信，所以
``OPENAI_SMS_COUNTRIES`` 白名单之外的国家在自动选号时会打告警但不阻止。
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

import requests

logger = logging.getLogger(__name__)

SMS_DEFAULT_SERVICE = "dr"
SMS_DEFAULT_COUNTRY = "52"  # 泰国 —— OpenAI 走纯 SMS 的稳定国家
SMS_PHONE_LIFETIME = 20 * 60  # 号码租用窗口（秒）

# OpenAI 走纯 SMS 的国家白名单（截至 2025-2026 实测；其它国家会抽到 WhatsApp 号）
OPENAI_SMS_COUNTRIES = {"52"}

SMS_PROVIDERS: dict[str, dict[str, str]] = {
    "smsbower": {
        "label": "SmsBower",
        "base_url": "https://smsbower.page/stubs/handler_api.php",
    },
    "herosms": {
        "label": "HeroSMS",
        "base_url": "https://hero-sms.com/stubs/handler_api.php",
    },
}

_SMS_CACHE_LOCK = threading.Lock()
_SMS_VERIFY_LOCK = threading.RLock()
_SMS_CACHE: Optional[dict] = None  # 跨线程共享的号码复用缓存


@dataclass
class SmsActivation:
    """一次手机号租用的句柄。"""

    activation_id: str
    phone_number: str  # E.164 格式，带 + 前缀
    country: str = ""
    metadata: dict = field(default_factory=dict)


class BaseSmsProvider(ABC):
    """接码 provider 抽象基类。"""

    auto_report_success_on_code = True  # True = 收到码即报成功；False = 等业务侧确认

    @abstractmethod
    def get_number(
        self,
        *,
        service: str,
        country: str = "",
        country_candidates: Optional[list[str]] = None,
    ) -> SmsActivation:
        ...

    @abstractmethod
    def get_code(self, activation_id: str, *, timeout: int = 180) -> str:
        ...

    @abstractmethod
    def cancel(self, activation_id: str) -> bool:
        ...

    def get_balance(self) -> float:
        """查询余额（货币随平台）。"""
        raise NotImplementedError

    def report_success(self, activation_id: str) -> bool:
        """业务侧验证通过后调用，平台据此结算并允许复用。"""
        return True

    def mark_code_failed(self, activation_id: str, reason: str = "") -> None:
        """业务侧收到码但 validate 失败 → 请求 resend。"""

    def mark_send_failed(self, activation_id: str, reason: str = "") -> None:
        """业务侧拒绝该手机号（add-phone/send 返错）→ 停止复用并退款。"""

    def mark_send_succeeded(self, activation_id: str) -> None:
        """业务侧已成功触发短信发送（add-phone/send 200）。"""

    def set_resend_callback(self, callback: Optional[Callable[[], None]]) -> None:
        """注册 resend 钩子，长等待时回调业务侧重新触发 OTP。"""


SMS_COUNTRY_NAMES_CN: dict[str, str] = {
    "0": "俄罗斯", "1": "乌克兰", "2": "哈萨克斯坦", "3": "中国", "4": "菲律宾",
    "5": "缅甸", "6": "印度尼西亚", "7": "马来西亚", "8": "肯尼亚", "9": "坦桑尼亚",
    "10": "越南", "11": "吉尔吉斯斯坦", "12": "美国(虚拟)", "13": "以色列", "14": "香港",
    "15": "波兰", "16": "英国", "17": "马达加斯加", "18": "刚果(布)", "19": "尼日利亚",
    "20": "澳门", "21": "埃及", "22": "印度", "23": "爱尔兰", "24": "柬埔寨",
    "25": "老挝", "26": "海地", "27": "科特迪瓦", "28": "冈比亚", "29": "塞尔维亚",
    "30": "也门", "31": "南非", "32": "罗马尼亚", "33": "哥伦比亚", "34": "爱沙尼亚",
    "35": "阿塞拜疆", "36": "加拿大", "37": "摩洛哥", "38": "加纳", "39": "阿根廷",
    "40": "乌兹别克斯坦", "41": "喀麦隆", "42": "乍得", "43": "德国", "44": "立陶宛",
    "45": "克罗地亚", "46": "瑞典", "47": "伊拉克", "48": "荷兰", "49": "拉脱维亚",
    "50": "奥地利", "51": "白俄罗斯", "52": "泰国", "53": "沙特阿拉伯", "54": "墨西哥",
    "55": "台湾", "56": "西班牙", "57": "伊朗", "58": "阿尔及利亚", "59": "斯洛文尼亚",
    "60": "孟加拉国", "61": "塞内加尔", "62": "土耳其", "63": "捷克", "64": "斯里兰卡",
    "65": "秘鲁", "66": "巴基斯坦", "67": "新西兰", "68": "几内亚", "69": "马里",
    "70": "委内瑞拉", "71": "埃塞俄比亚", "72": "蒙古", "73": "巴西", "74": "阿富汗",
    "75": "乌干达", "76": "安哥拉", "77": "塞浦路斯", "78": "法国", "79": "巴布亚新几内亚",
    "80": "莫桑比克", "81": "尼泊尔", "82": "比利时", "83": "保加利亚", "84": "匈牙利",
    "85": "摩尔多瓦", "86": "意大利", "87": "巴拉圭", "88": "洪都拉斯", "89": "突尼斯",
    "90": "尼加拉瓜", "91": "东帝汶", "92": "玻利维亚", "93": "哥斯达黎加", "94": "危地马拉",
    "95": "阿联酋", "96": "津巴布韦", "97": "波多黎各", "98": "苏丹", "99": "多哥",
    "100": "科威特", "101": "萨尔瓦多", "102": "利比亚", "103": "牙买加", "104": "特立尼达和多巴哥",
    "105": "厄瓜多尔", "106": "斯威士兰", "107": "阿曼", "108": "波黑", "109": "多米尼加",
    "110": "叙利亚", "111": "卡塔尔", "112": "巴拿马", "113": "古巴", "114": "毛里塔尼亚",
    "115": "塞拉利昂", "116": "约旦", "117": "葡萄牙", "118": "巴巴多斯", "119": "布隆迪",
    "120": "贝宁", "121": "文莱", "122": "巴哈马", "123": "博茨瓦纳", "124": "伯利兹",
    "125": "中非", "126": "多米尼克", "127": "格林纳达", "128": "格鲁吉亚", "129": "希腊",
    "130": "几内亚比绍", "131": "圭亚那", "132": "冰岛", "133": "科摩罗", "134": "利比里亚",
    "135": "莱索托", "136": "马拉维", "137": "纳米比亚", "138": "尼日尔", "139": "卢旺达",
    "140": "斯洛伐克", "141": "苏里南", "142": "塔吉克斯坦", "143": "摩纳哥", "144": "巴林",
    "145": "留尼汪岛", "146": "赞比亚", "147": "亚美尼亚", "148": "索马里", "149": "刚果(金)",
    "150": "智利", "151": "布基纳法索", "152": "黎巴嫩", "153": "加蓬", "154": "阿尔巴尼亚",
    "155": "乌拉圭", "156": "毛里求斯", "157": "不丹", "158": "马尔代夫", "159": "瓜德罗普岛",
    "160": "土库曼斯坦", "161": "法属圭亚那", "162": "芬兰", "163": "圣卢西亚", "164": "卢森堡",
    "165": "圣文森特", "166": "赤道几内亚", "167": "吉布提", "168": "安提瓜和巴布达", "169": "开曼群岛",
    "170": "黑山", "171": "丹麦", "172": "瑞士", "173": "挪威", "174": "澳大利亚",
    "175": "厄立特里亚", "176": "南苏丹", "177": "圣多美", "178": "阿鲁巴岛", "179": "蒙特塞拉特",
    "180": "安圭拉岛", "181": "北马其顿", "182": "塞舌尔", "183": "新喀里多尼亚", "184": "佛得角",
    "185": "美国(实体)", "186": "巴勒斯坦", "187": "美国", "188": "中国", "189": "韩国",
    "190": "科特迪瓦", "191": "日本",
}


def country_label(country_id) -> str:
    """返回 ``52 泰国`` 这样的展示标签。"""
    cid = str(country_id or "").strip()
    return f"{cid} {SMS_COUNTRY_NAMES_CN.get(cid, '')}".strip()


def _hash_secret(value: str) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def _safe_int(value, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError, AttributeError):
        return default


def _safe_float(value, default: float) -> float:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError, AttributeError):
        return default


def _safe_bool(value, default: bool) -> bool:
    if value in (None, ""):
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in {"0", "false", "no", "off", "否"}


def _cache_file() -> Path:
    cache_dir = Path(__file__).resolve().parents[1] / "data"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / ".sms_phone_cache.json"


def _parse_sms_status_text(text: str) -> dict:
    text = str(text or "").strip()
    if text == "STATUS_WAIT_CODE":
        return {"status": "wait_code"}
    if text.startswith("STATUS_WAIT_RETRY"):
        return {"status": "wait_retry", "raw": text}
    if text == "STATUS_WAIT_RESEND":
        return {"status": "wait_resend"}
    if text.startswith("STATUS_OK:"):
        return {"status": "ok", "code": text.split(":", 1)[1]}
    if text == "STATUS_CANCEL":
        return {"status": "cancel"}
    return {"status": "unknown", "raw": text}


def _make_sms_candidate(activation_id: str, source: str, code) -> Optional[dict]:
    code = str(code or "").strip()
    if not code or code in {"null", "None"}:
        return None
    return {
        "status": "ok",
        "code": code,
        "source": source,
        "sms_key": hashlib.sha256(f"{activation_id}:{code}".encode("utf-8")).hexdigest(),
    }


class SmsActivateProvider(BaseSmsProvider):
    """sms-activate 协议系 provider（SmsBower / HeroSMS 共用）。"""

    DEFAULT_BASE_URL = SMS_PROVIDERS["smsbower"]["base_url"]
    auto_report_success_on_code = False  # 等业务侧确认才报成功，便于号码复用

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = "",
        default_service: str = SMS_DEFAULT_SERVICE,
        default_country: str = SMS_DEFAULT_COUNTRY,
        max_price: float = -1,
        fixed_price: float = -1,
        proxy: Optional[str] = None,
        reuse_phone_to_max: bool = True,
        phone_success_max: int = 3,
    ):
        self.api_key = str(api_key or "").strip()
        self.base_url = str(base_url or "").strip() or self.DEFAULT_BASE_URL
        self.default_service = str(default_service or SMS_DEFAULT_SERVICE).strip()
        self.default_country = str(default_country or SMS_DEFAULT_COUNTRY).strip()
        self.max_price = float(max_price or -1)
        self.fixed_price = float(fixed_price or -1)
        self._proxy = (proxy or "").strip() or None
        self._proxies = {"http": self._proxy, "https": self._proxy} if self._proxy else None
        self.reuse_phone_to_max = bool(reuse_phone_to_max)
        self.phone_success_max = max(0, int(phone_success_max or 0))
        self._resend_callback: Optional[Callable[[], None]] = None
        self.last_code_result: Optional[dict] = None
        self.current_activation: Optional[SmsActivation] = None

    # ── HTTP ──

    def _request(self, params: dict, *, needs_key: bool = True, timeout: int = 30):
        payload = dict(params)
        if needs_key:
            payload["api_key"] = self.api_key
        resp = requests.get(self.base_url, params=payload, timeout=timeout, proxies=self._proxies)
        resp.raise_for_status()
        return resp

    # ── 余额 / 价格 / 国家 ──

    def get_balance(self) -> float:
        text = self._request({"action": "getBalance"}).text.strip()
        if text.startswith("ACCESS_BALANCE:"):
            return float(text.split(":", 1)[1])
        raise RuntimeError(f"查询余额失败: {text}")

    def get_prices(self, service: Optional[str] = None, country=None) -> dict:
        params = {"action": "getPrices"}
        if service:
            params["service"] = service
        if country not in (None, ""):
            params["country"] = country
        data = self._request(params).json()
        if isinstance(data, dict):
            return data
        raise RuntimeError("getPrices 返回结构异常")

    def get_top_countries(self, service: Optional[str] = None) -> list[dict]:
        """按价格升序、库存降序返回国家列表。"""
        service_code = str(service or self.default_service or SMS_DEFAULT_SERVICE).strip()
        for action in ("getTopCountriesByServiceRank", "getTopCountriesByService"):
            try:
                data = self._request({"action": action, "service": service_code}).json()
                rows = self._parse_top_countries(data)
                if rows:
                    rows.sort(key=lambda r: (r.get("price") or 999, -(r.get("count") or 0)))
                    return rows
            except Exception:
                continue

        # 排名 API 不可用时退回 getPrices 自己算
        try:
            prices = self.get_prices(service=service_code)
        except Exception:
            return []
        rows = []
        for country_id, services in prices.items():
            if not isinstance(services, dict):
                continue
            entry = services.get(service_code)
            if not isinstance(entry, dict):
                continue
            price = _safe_float(entry.get("cost") or entry.get("price"), -1)
            count = _safe_int(entry.get("count") or entry.get("qty") or entry.get("available"), 0)
            if price >= 0 and count > 0:
                rows.append({"country": str(country_id), "price": price, "count": count})
        rows.sort(key=lambda r: (r.get("price") or 999, -(r.get("count") or 0)))
        return rows

    @staticmethod
    def _parse_top_countries(data) -> list[dict]:
        items = data
        if isinstance(data, dict):
            items = data.get("data") or data.get("result") or data.get("response") or data

        rows: list[dict] = []
        if isinstance(items, dict):
            for key, value in items.items():
                if not isinstance(value, dict):
                    continue
                try:
                    country_id = str(int(key))
                except (TypeError, ValueError):
                    continue
                price = _safe_float(
                    value.get("price") or value.get("cost") or value.get("retail_price"), -1
                )
                count = _safe_int(value.get("count") or value.get("qty") or value.get("available"), 0)
                if price >= 0:
                    rows.append({"country": country_id, "price": price, "count": count})
        elif isinstance(items, list):
            for item in items:
                if not isinstance(item, dict):
                    continue
                country_id = (
                    item.get("country")
                    or item.get("countryId")
                    or item.get("country_id")
                    or item.get("id")
                )
                if country_id is None:
                    continue
                price = _safe_float(item.get("price") or item.get("cost"), -1)
                count = _safe_int(item.get("count") or item.get("qty") or item.get("available"), 0)
                if price >= 0:
                    rows.append({"country": str(country_id), "price": price, "count": count})
        return rows

    def get_best_country(
        self,
        service: Optional[str] = None,
        *,
        min_stock: int = 20,
        max_price: float = 0,
        strict_whitelist: bool = False,
        allowed_countries: Optional[list[str]] = None,
    ) -> Optional[str]:
        """自动选最优国家。

        ``allowed_countries`` 优先级最高（从这些国家里挑最便宜且库存足的）；
        其次 ``strict_whitelist`` 只从 ``OPENAI_SMS_COUNTRIES`` 里选；都没设
        就全平台自由选，由调用方承担"OpenAI 让用 WhatsApp"的风险。
        """
        try:
            rows = self.get_top_countries(service=service)
        except Exception as exc:
            logger.warning("查询国家排名失败: %s", exc)
            return None
        if not rows:
            return None

        allowed_set: Optional[set[str]] = None
        if allowed_countries:
            allowed_set = {str(c).strip() for c in allowed_countries if str(c).strip()}

        def _pick(stock_threshold: int) -> Optional[str]:
            for row in rows:
                cid = str(row.get("country") or "")
                if allowed_set is not None:
                    if cid not in allowed_set:
                        continue
                elif strict_whitelist and cid not in OPENAI_SMS_COUNTRIES:
                    continue
                price = row.get("price") or 0
                count = row.get("count") or 0
                if count < stock_threshold:
                    continue
                if max_price > 0 and price > max_price:
                    continue
                if not strict_whitelist and cid not in OPENAI_SMS_COUNTRIES:
                    logger.warning(
                        "自动选中非 OpenAI-SMS 白名单国家 country=%s price=%s"
                        "（OpenAI 可能让此号走 WhatsApp 验证，收不到短信）",
                        cid,
                        price,
                    )
                return cid
            return None

        return _pick(min_stock) or _pick(1)

    # ── 号码复用缓存 ──

    def _cache_identity(self, service: str, country: str) -> dict:
        return {
            "api_key_hash": _hash_secret(self.api_key),
            "service": str(service),
            "country": str(country),
        }

    def _load_cache(self, service: str, country: str) -> Optional[dict]:
        global _SMS_CACHE
        cache = _SMS_CACHE
        if cache is None:
            path = _cache_file()
            if not path.exists():
                return None
            try:
                cache = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                return None

        identity = self._cache_identity(service, country)
        if any(str(cache.get(k) or "") != str(v) for k, v in identity.items()):
            return None

        elapsed = time.time() - float(cache.get("acquired_at") or 0)
        if elapsed >= SMS_PHONE_LIFETIME or cache.get("reuse_stopped"):
            self._clear_cache()
            return None
        if self.phone_success_max > 0 and int(cache.get("use_count") or 0) >= self.phone_success_max:
            cache["reuse_stopped"] = True
            cache["stop_reason"] = f"已达单号复用上限 ({self.phone_success_max})"
            self._save_cache(cache)
            return None

        cache["used_codes"] = set(cache.get("used_codes") or [])
        _SMS_CACHE = cache
        return cache

    def _save_cache(self, cache: Optional[dict]) -> None:
        global _SMS_CACHE
        _SMS_CACHE = cache
        path = _cache_file()
        if cache is None:
            try:
                path.unlink(missing_ok=True)
            except Exception:
                pass
            return
        serializable = dict(cache)
        serializable["used_codes"] = sorted(serializable.get("used_codes") or [])
        path.write_text(json.dumps(serializable, ensure_ascii=False), encoding="utf-8")

    def _clear_cache(self) -> None:
        self._save_cache(None)

    # ── 租号 ──

    def _request_number(self, action: str, service: str, country: str) -> dict:
        """单次调用 getNumberV2 或 getNumber，失败原样抛给调用方的双重循环。"""
        params = {"action": action, "service": service, "country": country}
        if self.fixed_price > 0:
            # HeroSMS 用 fixedPrice 开关；SmsBower 要求 minPrice == maxPrice 才算固定价
            if "hero-sms.com" in self.base_url:
                params["maxPrice"] = self.fixed_price
                params["fixedPrice"] = "true"
            else:
                params["minPrice"] = self.fixed_price
                params["maxPrice"] = self.fixed_price
        elif self.max_price > 0:
            params["maxPrice"] = self.max_price

        logger.info(
            "接码 %s: service=%s country=%s maxPrice=%s",
            action,
            service,
            country,
            params.get("maxPrice", "未设置"),
        )
        resp = self._request(params)
        resp_text = resp.text.strip()

        if action == "getNumberV2":
            try:
                data = resp.json()
            except ValueError:
                data = None
            if isinstance(data, dict) and data.get("activationId"):
                return data
            raise RuntimeError(resp_text[:200] or "空响应")

        if resp_text.startswith("ACCESS_NUMBER:"):
            parts = resp_text.split(":", 2)
            if len(parts) == 3:
                return {
                    "activationId": parts[1],
                    "phoneNumber": parts[2],
                    "countryPhoneCode": "",
                }
        raise RuntimeError(resp_text[:200] or "空响应")

    @staticmethod
    def _format_phone(info: dict) -> str:
        raw = str(info.get("phoneNumber") or "").strip()
        code = str(info.get("countryPhoneCode") or "").strip()
        if raw.startswith("+"):
            return raw
        if code and raw.startswith(code):
            return f"+{raw}"
        if code:
            return f"+{code}{raw}"
        return f"+{raw}"

    def get_number(
        self,
        *,
        service: str,
        country: str = "",
        country_candidates: Optional[list[str]] = None,
    ) -> SmsActivation:
        """租号，按候选国家顺序依次尝试，每个国家先试 V2 再退 V1。"""
        service_code = str(self.default_service or service or SMS_DEFAULT_SERVICE).strip()
        if not country_candidates:
            country_candidates = [
                str(country or self.default_country or SMS_DEFAULT_COUNTRY).strip()
            ]

        with _SMS_VERIFY_LOCK, _SMS_CACHE_LOCK:
            cache = (
                self._load_cache(service_code, country_candidates[0])
                if self.reuse_phone_to_max
                else None
            )
            if cache and str(cache.get("country") or "") in country_candidates:
                activation = SmsActivation(
                    activation_id=str(cache["activation_id"]),
                    phone_number=str(cache["phone_number"]),
                    country=str(cache.get("country") or country_candidates[0]),
                    metadata={"reused": True, "use_count": int(cache.get("use_count") or 0)},
                )
                self.current_activation = activation
                return activation

            failures: list[str] = []
            last_exc: Optional[Exception] = None
            for cid in country_candidates:
                cid = str(cid).strip()
                if not cid:
                    continue
                for action in ("getNumberV2", "getNumber"):
                    try:
                        info = self._request_number(action, service_code, cid)
                    except Exception as exc:
                        failures.append(f"{cid}: {action}={str(exc)[:120]}")
                        last_exc = exc
                        continue

                    activation_id = str(info.get("activationId") or "")
                    phone = self._format_phone(info)
                    if not activation_id or not phone.strip("+"):
                        failures.append(f"{cid}: {action} 返回信息不完整")
                        continue

                    self._save_cache(
                        {
                            **self._cache_identity(service_code, cid),
                            "country": cid,
                            "activation_id": activation_id,
                            "phone_number": phone,
                            "acquired_at": time.time(),
                            "use_count": 0,
                            "used_codes": set(),
                            "reuse_stopped": False,
                            "stop_reason": "",
                        }
                    )
                    activation = SmsActivation(
                        activation_id=activation_id,
                        phone_number=phone,
                        country=cid,
                        metadata={"reused": False},
                    )
                    self.current_activation = activation
                    if len(country_candidates) > 1:
                        logger.info("在国家 %s 租到号 %s (action=%s)", cid, phone, action)
                    return activation

            detail = " | ".join(failures) if failures else "未知"
            raise RuntimeError(
                f"依次尝试 {len(country_candidates)} 个候选国家全部失败: {detail}"
            ) from last_exc

    # ── 等码 / 状态查询 ──

    def get_status(self, activation_id: str) -> dict:
        return _parse_sms_status_text(
            self._request({"action": "getStatus", "id": activation_id}).text
        )

    def get_status_v2(self, activation_id: str) -> dict:
        resp = self._request({"action": "getStatusV2", "id": activation_id})
        try:
            data = resp.json()
        except ValueError:
            return _parse_sms_status_text(resp.text.strip())

        if isinstance(data, str):
            return _parse_sms_status_text(data)
        if not isinstance(data, dict):
            return {"status": "unknown"}

        raw_status = data.get("status")
        if isinstance(raw_status, str):
            parsed = _parse_sms_status_text(raw_status)
            if parsed.get("status") != "unknown":
                return parsed
        for channel in ("sms", "call"):
            item = data.get(channel)
            if isinstance(item, dict):
                candidate = _make_sms_candidate(
                    activation_id, f"getStatusV2.{channel}", item.get("code")
                )
                if candidate:
                    return candidate
        return {"status": "wait_code"}

    def request_resend_sms(self, activation_id: str) -> bool:
        try:
            self._request({"action": "setStatus", "id": activation_id, "status": 3})
            return True
        except Exception:
            return False

    def wait_for_code(
        self,
        activation_id: str,
        *,
        timeout: int = 80,
        poll: int = 3,
        openai_resend_interval: int = 20,
        openai_resend_max: int = 3,
    ) -> Optional[dict]:
        """等短信验证码。

        每 ``openai_resend_interval`` 秒触发一次业务侧 resend（最多
        ``openai_resend_max`` 次）并同步请求平台侧 resend；超时返回 None，
        由上层 cancel 换号。
        """
        start = time.time()
        deadline = start + timeout
        resend_count = 0
        last_platform_resend = start
        with _SMS_CACHE_LOCK:
            used_codes = set((_SMS_CACHE or {}).get("used_codes") or [])

        while time.time() < deadline:
            for source in ("v2", "v1"):
                try:
                    result = (
                        self.get_status_v2(activation_id)
                        if source == "v2"
                        else self.get_status(activation_id)
                    )
                except Exception as exc:
                    logger.debug("查询接码状态 %s 失败: %s", source, exc)
                    continue
                if result.get("status") == "cancel":
                    return None
                if result.get("status") == "ok":
                    code = str(result.get("code") or "")
                    if code and code not in used_codes:
                        return {
                            "status": "ok",
                            "code": code,
                            "sms_key": result.get("sms_key") or "",
                        }

            elapsed = time.time() - start
            expected_resend = min(openai_resend_max, int(elapsed // openai_resend_interval))
            if expected_resend > resend_count and self._resend_callback:
                try:
                    self._resend_callback()
                    resend_count = expected_resend
                    logger.info(
                        "已请求业务侧 resend (第 %d/%d 次, elapsed=%ds)",
                        resend_count,
                        openai_resend_max,
                        int(elapsed),
                    )
                except Exception as exc:
                    logger.warning("业务侧 resend 回调失败: %s", exc)
                self.request_resend_sms(activation_id)
                last_platform_resend = time.time()
            elif time.time() - last_platform_resend >= openai_resend_interval:
                self.request_resend_sms(activation_id)
                last_platform_resend = time.time()

            time.sleep(poll)
        return None

    def get_code(self, activation_id: str, *, timeout: int = 180) -> str:
        # 传进来的 timeout 就是真 timeout：号码有 20 分钟生命周期，但 OpenAI 那边的
        # phone-otp challenge 等不了那么久，超时就该让上层换号。
        candidate = self.wait_for_code(activation_id, timeout=timeout)
        self.last_code_result = candidate
        return str((candidate or {}).get("code") or "")

    # ── 状态报告 ──

    def cancel(self, activation_id: str) -> bool:
        ok = False
        try:
            resp = self._request({"action": "cancelActivation", "id": activation_id})
            ok = resp.status_code == 204 or "ACCESS_CANCEL" in resp.text
        except Exception:
            ok = False
        if not ok:
            try:
                resp = self._request({"action": "setStatus", "id": activation_id, "status": 8})
                ok = "ACCESS_CANCEL" in resp.text
            except Exception:
                ok = False
        with _SMS_CACHE_LOCK:
            cache = _SMS_CACHE
            if cache and str(cache.get("activation_id")) == str(activation_id):
                self._clear_cache()
        return ok

    def report_success(self, activation_id: str) -> bool:
        with _SMS_CACHE_LOCK:
            cache = _SMS_CACHE
            should_finish = False
            should_clear = False
            if cache and str(cache.get("activation_id")) == str(activation_id):
                cache["use_count"] = int(cache.get("use_count") or 0) + 1
                if self.last_code_result and self.last_code_result.get("code"):
                    used = set(cache.get("used_codes") or [])
                    used.add(self.last_code_result["code"])
                    cache["used_codes"] = used
                remaining = SMS_PHONE_LIFETIME - (time.time() - float(cache.get("acquired_at") or 0))
                if not self.reuse_phone_to_max:
                    should_finish = should_clear = True
                    cache["reuse_stopped"] = True
                elif self.phone_success_max > 0 and int(cache["use_count"]) >= self.phone_success_max:
                    should_finish = True
                    cache["reuse_stopped"] = True
                elif remaining <= 30:
                    should_finish = should_clear = True
                    cache["reuse_stopped"] = True
                self._save_cache(cache)
                if should_clear:
                    self._clear_cache()
            holds_cache = bool(cache and str(cache.get("activation_id")) == str(activation_id))

        if not (should_finish or not holds_cache):
            return True
        try:
            resp = self._request({"action": "finishActivation", "id": activation_id})
            return resp.status_code in (200, 204) or "ACCESS" in resp.text
        except Exception:
            try:
                resp = self._request({"action": "setStatus", "id": activation_id, "status": 6})
                return "ACCESS" in resp.text
            except Exception:
                return False

    def mark_code_failed(self, activation_id: str, reason: str = "") -> None:
        with _SMS_CACHE_LOCK:
            cache = _SMS_CACHE
            if cache and str(cache.get("activation_id")) == str(activation_id):
                if self.last_code_result and self.last_code_result.get("code"):
                    used = set(cache.get("used_codes") or [])
                    used.add(self.last_code_result["code"])
                    cache["used_codes"] = used
                self._save_cache(cache)
        if self._resend_callback:
            try:
                self._resend_callback()
            except Exception:
                pass
        self.request_resend_sms(activation_id)

    def mark_send_succeeded(self, activation_id: str) -> None:
        try:
            self._request({"action": "setStatus", "id": activation_id, "status": 1})
        except Exception:
            pass

    def mark_send_failed(self, activation_id: str, reason: str = "") -> None:
        # 业务侧拒了这个号 → cancel 退款，号根本没用上，不能白花钱
        cancelled = False
        try:
            resp = self._request({"action": "setStatus", "id": activation_id, "status": 8})
            cancelled = "ACCESS_CANCEL" in resp.text or resp.status_code in (200, 204)
        except Exception:
            cancelled = False
        logger.info(
            "号 activation_id=%s 退款%s（原因: %s）",
            activation_id,
            "成功" if cancelled else "失败",
            (reason or "未知原因")[:80],
        )
        with _SMS_CACHE_LOCK:
            cache = _SMS_CACHE
            if cache and str(cache.get("activation_id")) == str(activation_id):
                cache["reuse_stopped"] = True
                cache["stop_reason"] = reason or "号码被业务侧拒绝"
                self._save_cache(cache)
                self._clear_cache()

    def set_resend_callback(self, callback: Optional[Callable[[], None]]) -> None:
        self._resend_callback = callback


def create_sms_provider(provider_key: str, config: dict) -> BaseSmsProvider:
    """从配置创建 provider 实例。

    ``provider_key`` 取 ``smsbower`` / ``herosms``；配置字段见
    ``api/config.py`` 里的 ``sms_*`` 系列。
    """
    key = (provider_key or "").lower().strip().replace("_", "")
    meta = SMS_PROVIDERS.get(key)
    if meta is None:
        raise RuntimeError(f"未知接码服务: {provider_key}")

    api_key = str(config.get("sms_api_key") or "").strip()
    if not api_key:
        raise RuntimeError(f"{meta['label']} 未配置 API Key")

    return SmsActivateProvider(
        api_key=api_key,
        base_url=meta["base_url"],
        default_service=str(config.get("sms_service") or "").strip() or SMS_DEFAULT_SERVICE,
        default_country=str(config.get("sms_country") or "").strip() or SMS_DEFAULT_COUNTRY,
        max_price=_safe_float(config.get("sms_max_price"), -1),
        fixed_price=_safe_float(config.get("sms_fixed_price"), -1),
        proxy=(str(config.get("sms_proxy") or config.get("proxy") or "")).strip() or None,
        reuse_phone_to_max=_safe_bool(config.get("sms_reuse_phone"), False),
        phone_success_max=max(0, _safe_int(config.get("sms_phone_success_max"), 3)),
    )


class PhoneCallbackController:
    """把接码 provider 包装成两阶段回调，注入 ``AuthFlow`` 的 add-phone 流程。"""

    def __init__(
        self,
        provider_key: str,
        config: dict,
        *,
        service: str = "openai",
        country: str = "",
        log_fn: Optional[Callable[[str], None]] = None,
        auto_select_country: bool = False,
    ):
        self.provider_key = provider_key
        self.config = dict(config or {})
        self.service = service
        self.country = country
        self.log = log_fn or logger.info
        self.auto_select_country = bool(auto_select_country)
        self.provider: Optional[BaseSmsProvider] = None
        self.activation: Optional[SmsActivation] = None
        self.completed = False
        self._verify_lock_acquired = False
        self._warned_off_whitelist = False

    def _ensure_provider(self) -> BaseSmsProvider:
        if self.provider is None:
            self.provider = create_sms_provider(self.provider_key, self.config)
        return self.provider

    def get_phone(self) -> str:
        """阶段 1：租手机号（返回带 + 的 E.164）。"""
        provider = self._ensure_provider()
        # 同号复用锁，防止两个注册任务并发抢同一份缓存
        if isinstance(provider, SmsActivateProvider) and not self._verify_lock_acquired:
            _SMS_VERIFY_LOCK.acquire()
            self._verify_lock_acquired = True

        candidates = self._resolve_country_candidates(provider)
        preview = ",".join(
            f"{c}({SMS_COUNTRY_NAMES_CN.get(c, '?')})" for c in candidates[:5]
        )
        self.log(
            f"准备租号: provider={self.provider_key} service={self.service} "
            f"候选={preview}{' …' if len(candidates) > 5 else ''}"
        )

        try:
            self.activation = provider.get_number(
                service=self.service,
                country=candidates[0],
                country_candidates=candidates,
            )
        except Exception:
            self._release_lock()
            raise

        reused = bool((self.activation.metadata or {}).get("reused"))
        used_country = self.activation.country or candidates[0]
        self.log(
            f"已租到号码{'（复用）' if reused else ''}: {self.activation.phone_number} "
            f"国家={country_label(used_country)} "
            f"(activation_id={self.activation.activation_id})"
        )
        # 白名单外的号段，OpenAI 常把验证改走 WhatsApp，接码平台就永远等不到短信。
        # 这时"发送成功但收不到码"看起来像平台的问题，其实是选错了国家。
        if used_country not in OPENAI_SMS_COUNTRIES and not self._warned_off_whitelist:
            self._warned_off_whitelist = True
            whitelist = "、".join(country_label(c) for c in sorted(OPENAI_SMS_COUNTRIES))
            self.log(
                f"提醒: {country_label(used_country)} 不在 OpenAI 纯短信白名单（{whitelist}）；"
                "这些号段 OpenAI 可能改用 WhatsApp 发码，会出现"
                "「发送成功但一直等不到短信」"
            )
        return self.activation.phone_number

    def _resolve_country_candidates(self, provider: BaseSmsProvider) -> list[str]:
        allowed_raw = str(self.config.get("sms_allowed_countries") or "").strip()
        allowed = [c.strip() for c in allowed_raw.replace(";", ",").split(",") if c.strip()]

        if not (self.auto_select_country and isinstance(provider, SmsActivateProvider)):
            return [self.country] if self.country else [SMS_DEFAULT_COUNTRY]

        if allowed:
            self.log(f"自动选号: 从勾选的 {len(allowed)} 个国家按价格升序依次尝试")
            try:
                rows = provider.get_top_countries(service=self.service)
            except Exception as exc:
                self.log(f"排名查询失败（{exc}），按勾选的原始顺序尝试")
                return list(allowed)
            ranked = [str(r["country"]) for r in rows if str(r.get("country") or "") in allowed]
            candidates = ranked + [c for c in allowed if c not in ranked]
            self.log(f"候选顺序: {','.join(candidates)}")
            return candidates or [SMS_DEFAULT_COUNTRY]

        self.log("自动选号: 未指定允许国家，按全平台价格 + 库存挑最优")
        try:
            best = provider.get_best_country(
                service=self.service,
                min_stock=_safe_int(self.config.get("sms_auto_min_stock"), 20),
                max_price=_safe_float(self.config.get("sms_auto_max_price"), 0),
                strict_whitelist=_safe_bool(self.config.get("sms_strict_whitelist"), False),
            )
        except Exception as exc:
            self.log(f"国家智能选择失败（{exc}），使用默认国家")
            best = ""
        if best:
            in_whitelist = best in OPENAI_SMS_COUNTRIES
            self.log(
                f"自动选择国家: {country_label(best)} "
                f"[{'OpenAI SMS 白名单' if in_whitelist else '非白名单，可能走 WhatsApp'}]"
            )
            return [best]

        self.log("未找到满足条件的国家，使用默认国家")
        return [self.country] if self.country else [SMS_DEFAULT_COUNTRY]

    def get_code(self, timeout: int = 180) -> str:
        """阶段 2：等待短信验证码。"""
        if not self.activation:
            raise RuntimeError("尚未租号，无法等待验证码")
        provider = self._ensure_provider()
        self.log(
            f"等待短信验证码…(activation_id={self.activation.activation_id} timeout={timeout}s)"
        )
        code = provider.get_code(self.activation.activation_id, timeout=timeout)
        if code:
            self.log(f"收到短信验证码: {code}")
            if getattr(provider, "auto_report_success_on_code", True):
                self.report_success()
        else:
            self.log(f"未收到短信验证码: activation_id={self.activation.activation_id}")
        return code

    def report_success(self) -> None:
        if self.activation and self.provider and not self.completed:
            try:
                self.provider.report_success(self.activation.activation_id)
            except Exception as exc:
                logger.warning("上报号码成功失败: %s", exc)
            self.completed = True
            self.log(f"号码已标记完成: activation_id={self.activation.activation_id}")
        self._release_lock()

    def mark_code_failed(self, reason: str = "") -> None:
        if self.activation and self.provider:
            try:
                self.provider.mark_code_failed(self.activation.activation_id, reason=reason)
            except Exception:
                pass

    def mark_send_succeeded(self) -> None:
        if self.activation and self.provider:
            try:
                self.provider.mark_send_succeeded(self.activation.activation_id)
            except Exception:
                pass

    def mark_send_failed(self, reason: str = "") -> None:
        if self.activation and self.provider:
            try:
                self.provider.mark_send_failed(self.activation.activation_id, reason=reason)
            except Exception:
                pass

    def set_resend_callback(self, callback: Optional[Callable[[], None]]) -> None:
        try:
            self._ensure_provider().set_resend_callback(callback)
        except Exception:
            pass

    def cleanup(self) -> None:
        """流程结束（成功或失败）调用：释放未完成的号并解锁。"""
        if self.activation and not self.completed and self.provider:
            try:
                self.provider.cancel(self.activation.activation_id)
                self.log(f"已释放未使用号码: activation_id={self.activation.activation_id}")
            except Exception:
                pass
            self.activation = None
        self._release_lock()

    def _release_lock(self) -> None:
        if self._verify_lock_acquired:
            try:
                _SMS_VERIFY_LOCK.release()
            except RuntimeError:
                pass
            self._verify_lock_acquired = False


def resolve_sms_settings(extra_config: Optional[dict] = None) -> dict:
    """把全局配置里的 ``sms_*`` 项和本次任务的覆盖合并成一份接码配置。"""
    from core.config_store import config_store

    settings = {
        key: value
        for key, value in (config_store.get_all() or {}).items()
        if key.startswith("sms_")
    }
    for key, value in (extra_config or {}).items():
        if key.startswith("sms_") and value not in (None, ""):
            settings[key] = value
    return settings


def build_phone_callback(
    settings: dict,
    *,
    log_fn: Optional[Callable[[str], None]] = None,
    proxy: Optional[str] = None,
) -> Optional[PhoneCallbackController]:
    """按配置构造接码控制器；未启用或缺 API Key 时返回 None。

    返回 None 意味着注册链路命中 add-phone 时会回退到手工号码路径
    （``OPENAI_PHONE_NUMBER`` 系列），行为跟没接接码时一致。
    """
    settings = dict(settings or {})
    if not _safe_bool(settings.get("sms_enabled"), False):
        return None

    if not str(settings.get("sms_api_key") or "").strip():
        logger.warning("已启用接码但未配置 sms_api_key，跳过接码")
        return None

    if proxy and not str(settings.get("sms_proxy") or "").strip():
        settings["sms_proxy"] = proxy

    # 服务码在租号和查国家排名两处都要用，必须同一个值：平台按服务码分库存，
    # 拿 "openai" 这种人类可读名去查排名只会得到空表。OpenAI 对应的是 dr。
    try:
        return PhoneCallbackController(
            provider_key=str(settings.get("sms_provider") or "smsbower"),
            config=settings,
            service=str(settings.get("sms_service") or "").strip() or SMS_DEFAULT_SERVICE,
            country=str(settings.get("sms_country") or "").strip() or SMS_DEFAULT_COUNTRY,
            log_fn=log_fn,
            auto_select_country=_safe_bool(settings.get("sms_auto_country"), False),
        )
    except Exception as exc:
        logger.warning("创建接码控制器失败: %s", exc)
        return None
