"""设备指纹：服务端生成 + 浏览器侧激活（两步分开）。

为什么生成能在服务端做
    App 里那份指纹来自 POST /udid/m1：服务端按账号 token 派生设备标识、按时间戳
    签发一个 token。所以只要拿到账号自己的龙湖 token，就能在服务端直接造一份与
    真机等价、且**一账号一份**的指纹（dxrisk 模块，纯标准库，无需浏览器）。

为什么激活必须回到浏览器
    签到用的请求头是 X-LF-DXRisk-Captcha-Token: "<滑块 token>:<指纹>"，滑块 token
    由 /api/v1 签发并和本次请求的 c（即指纹）绑定。过滑块要跑顶象 SDK 的 JS + 真实
    手势，所以放在**用户自己的浏览器**里做（app/static/slider.js），服务端只负责
    生成指纹、校验回落、落库——这样服务端零浏览器依赖，镜像不用装 chromium。

两步的时序
    prepare  → 生成指纹，暂存为 pending（10 分钟），返回给前端
    （前端）  → localStorage 写入指纹 → SDK 出题 → 自动拖 → 拿 captcha token
    commit   → 校验 pending 一致 → 写 dx_token
"""

import logging
import threading
import time

from . import dxrisk

log = logging.getLogger(__name__)

PENDING_TTL = 600.0          # pending 指纹的有效期（秒）
_pending: dict[int, tuple[str, float]] = {}
_lock = threading.Lock()


def generate(account: dict, overrides: dict | None = None,
             timeout: int = 20) -> tuple[str | None, str]:
    """按账号的龙湖 token 生成一份新指纹。返回 (指纹, 说明)。"""
    token = (account.get("token") or "").strip()
    if not token:
        return None, "账号没有可用的龙湖 token，无法生成指纹"
    try:
        res = dxrisk.issue(token, overrides=overrides or {}, timeout=timeout)
    except Exception as exc:
        log.exception("[%s] 生成指纹异常", account.get("name"))
        return None, f"生成指纹异常: {str(exc)[:120]}"

    value = (res.get("token") or "").strip()
    if not value:
        code = res.get("code")
        hint = {
            -10005: "服务端解不开请求（密钥/加密不符）",
            -10004: "请求体被拒（设备消息或设备信息字段不合法）",
            -10002: "业务校验未过（设备信息组合不自洽）",
        }.get(code, "")
        return None, f"生成失败：code={code}{('，' + hint) if hint else ''}"
    return value, f"已生成指纹（{res.get('ms', 0)} ms）"


def put_pending(account_id: int, fingerprint: str) -> None:
    with _lock:
        _pending[account_id] = (fingerprint, time.time())


def take_pending(account_id: int) -> str:
    """取出该账号待激活的指纹；过期或不存在返回空串。"""
    with _lock:
        item = _pending.get(account_id)
        if not item:
            return ""
        fingerprint, ts = item
        if time.time() - ts > PENDING_TTL:
            _pending.pop(account_id, None)
            return ""
        return fingerprint


def drop_pending(account_id: int) -> None:
    with _lock:
        _pending.pop(account_id, None)
