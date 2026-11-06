"""任务编排：续期 → 签到 → 状态刷新 → 落库 → 告警。"""

import logging
import math
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from . import db, dxidentity, longhu

logger = logging.getLogger(__name__)

BARK_DEFAULT_HOSTS = ("day.app",)
BARK_TITLE = "龙湖签到"
BOT_HOSTS = ("qyapi.weixin.qq.com", "oapi.dingtalk.com")


def days_left(expire_at: str | None) -> int | None:
    if not expire_at:
        return None
    try:
        dt = datetime.fromisoformat(expire_at)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = dt - datetime.now(timezone.utc)
        # 向上取整：刚续期完应显示 30 天，而不是 29 天
        return max(0, math.ceil(delta.total_seconds() / 86400))
    except Exception:
        return None


def _is_bark(url: str) -> bool:
    """判断是不是 Bark 地址。

    支持官方 https://api.day.app/<key> 和自建服务 https://bark.example.com/<key>。
    自建服务靠「路径只有一段、且不是群机器人域名」来判断。
    """
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if any(host == h or host.endswith("." + h) for h in BARK_DEFAULT_HOSTS):
        return True
    if any(bot in host for bot in BOT_HOSTS):
        return False
    segments = [s for s in parsed.path.split("/") if s]
    return len(segments) == 1 and not parsed.query


def _build_notify(url: str, text: str) -> tuple[str, dict]:
    """按 webhook 类型返回 (请求地址, 请求体)。

    - Bark：POST <origin>/push，body 里带 device_key
    - 企业微信 / 钉钉群机器人：{"msgtype": "text", ...}
    """
    if _is_bark(url):
        parsed = urlparse(url)
        key = [s for s in parsed.path.split("/") if s][0]
        scheme = parsed.scheme or "https"
        return f"{scheme}://{parsed.netloc}/push", {
            "device_key": key,
            "title": BARK_TITLE,
            "body": text,
            "group": BARK_TITLE,
        }
    return url, {"msgtype": "text", "text": {"content": text}}


def notify(text: str):
    """发告警（Bark / 企业微信 / 钉钉）。没配 webhook 就静默跳过。"""
    url = (db.get_settings().get("webhook_url") or "").strip()
    if not url:
        return

    endpoint, payload = _build_notify(url, text)
    session = requests.Session()
    session.trust_env = False  # 忽略系统代理，避免被本机抓包工具拦住
    try:
        resp = session.post(endpoint, json=payload, timeout=10)
        try:
            data = resp.json()
        except ValueError:
            data = {}
        # Bark 用 code（成功为 200），企业微信/钉钉用 errcode（成功为 0）
        code = data.get("code", data.get("errcode", 0))
        if resp.status_code >= 400 or code not in (0, 200):
            logger.warning("webhook 推送返回异常: HTTP %s %s", resp.status_code, data)
    except Exception as exc:  # 告警失败不影响主流程
        logger.warning("webhook 推送失败: %s", exc)
    finally:
        session.close()


APP_MODES = ("auto", "manual", "off")


def _dx_conflict(account: dict, accounts: list[dict]) -> list[dict]:
    """检查设备指纹是否与其他启用账号共用。

    2026-11-03 实测：同一个指纹用于多个账号会触发风控。因此指纹按 id 最小的
    账号归属，其余共用者视为冲突、暂停签到，直到换成独立指纹（重装 App 可换）。

    返回 id 更小的共用账号列表；空列表表示无冲突。
    """
    token = (account.get("dx_token") or "").strip()
    if not token:
        return []
    smaller = [
        a for a in accounts
        if a["id"] != account["id"]
        and (a.get("dx_token") or "").strip() == token
        and a["id"] < account["id"]
    ]
    return smaller


def _app_entry(account: dict, item: dict, mode: str) -> tuple[str, str]:
    """APP 专享签到入口。

    auto   ：用账号自己的设备指纹真去签（每个账号必须用独立指纹）
    manual ：只查状态，不打卡；未签就记 todo 交给每日汇总提醒人工去点
    off    ：完全不处理
    """
    label = "APP "
    if mode == "off":
        return "skipped", f"{label}已关闭"
    if not (account.get("dx_token") or "").strip():
        # 没指纹时先自动造一份（服务端生成，不需要浏览器）。造成功才继续；
        # 失败就退回 todo 提示用户点「补指纹」，不去硬打 udid/c1 那种必被判风险的现造指纹。
        fingerprint, message = dxidentity.generate(account)
        if not fingerprint:
            return "todo", f"{label}未配置设备指纹（{message}）。点「补指纹」生成一份"
        db.update_account(account["id"], dx_token=fingerprint)
        account["dx_token"] = fingerprint
        db.add_log(account["id"], account["name"], "dx", "ok",
                   f"首次签到自动生成指纹（{message}），激活前若报 8040012 请点「重置指纹」过滑块")
    if mode == "auto":
        return longhu.checkin(account, item["activity_no"], label)

    state = longhu.sign_state(account, item["activity_no"])
    if state is True:
        return "already", f"{label}今日已签到"
    if state is False:
        return "todo", f"{label}未签到，需在 App 内手动签（当前为 manual 模式）"
    return "todo", f"{label}状态未知，需在 App 内确认"


def run_account(account: dict, do_checkin: bool = True,
                app_mode: str | None = None,
                entries: tuple[str, ...] | None = None,
                with_profile: bool = True) -> dict:
    """执行单个账号的完整流程，返回可直接给前端用的结果。

    app_mode 为 None 时取设置里的 app_checkin_mode。
    entries 为 None 时两个入口都跑；只给一个入口时用于分时排期。
    with_profile=False 时跳过资料刷新，省一次请求（分时排期的第二个入口用）。
    """
    acc_id = account["id"]
    acc_name = account["name"]
    wanted = set(entries) if entries else {item["key"] for item in longhu.ACTIVITIES}
    result = {
        "account_id": acc_id,
        "name": acc_name,
        "refreshed": False,
        "checkin_status": "skipped",
        "checkin_message": "",
        "extra_signs": [],
        "profile": {},
        "error": "",
    }

    # ---- 1. 续期 ----
    try:
        ok, payload = longhu.refresh_token(account)
    except longhu.LonghuError as exc:
        ok, payload = False, str(exc)

    if ok:
        result["refreshed"] = True
        if payload != account.get("token"):
            db.update_account(acc_id, token=payload)
            account["token"] = payload
        db.update_account(acc_id, expire_at=longhu.expire_at())
        db.add_log(acc_id, acc_name, "refresh", "ok", "token 有效期已续至 30 天")
    else:
        db.add_log(acc_id, acc_name, "refresh", "fail", payload)
        result["error"] = payload
        logger.warning("[%s] 续期失败: %s", acc_name, payload)

    # ---- 1.5 设备指纹冲突检查 ----
    # 同一指纹被多个账号使用会触发风控（2026-11-03 实测）。指纹归 id 最小的
    # 账号所有，后来共用它的账号直接暂停签到——继续跑只会拖累整个设备。
    conflict = _dx_conflict(account, db.list_accounts(only_enabled=True))
    dx_block = ""
    if conflict:
        names = "、".join(a["name"] for a in conflict)
        dx_block = (
            f"设备指纹与「{names}」共用，已暂停签到：同一指纹多账号会触发风控。"
            "重装 App 可获得新指纹，之后点「换指纹」填入"
        )
        result["dx_conflict"] = [a["name"] for a in conflict]
        db.add_log(acc_id, acc_name, "dx", "fail", dx_block)

    # ---- 2. 签到（小程序 + APP 两个入口，同一天各签一次） ----
    if app_mode is None:
        app_mode = (db.get_settings().get("app_checkin_mode") or "auto").strip().lower()
    if app_mode not in APP_MODES:
        app_mode = "auto"

    extra = []
    if do_checkin and not dx_block:
        for item in longhu.ACTIVITIES:
            if item["key"] not in wanted:
                continue
            is_main = item["key"] == "mini"
            label = "" if is_main else "APP "
            try:
                if is_main:
                    status, message = longhu.checkin(account, item["activity_no"], label)
                else:
                    status, message = _app_entry(account, item, app_mode)
            except longhu.LonghuError as exc:
                status, message = "fail", str(exc)
            except Exception as exc:  # 单个入口异常不影响另一个
                logger.exception("[%s] %s 签到异常", acc_name, item["name"])
                status, message = "fail", f"异常: {exc}"

            db.add_log(acc_id, acc_name, "checkin" if is_main else "checkin_app",
                       status, message)
            if is_main:
                result["checkin_status"] = status
                result["checkin_message"] = message
                db.update_account(acc_id, last_status=status, last_message=message)
            else:
                extra.append({"key": item["key"], "name": item["name"],
                              "status": status, "message": message})

        result["extra_signs"] = extra
        if "mini" not in wanted and extra:
            # 只跑 APP 入口时，把结果挂到 checkin_status 方便排期判断，
            # 但不回写账号的 last_status——那是主签到（小程序）的状态标识。
            result["checkin_status"] = extra[0]["status"]
            result["checkin_message"] = extra[0]["message"]
        failed_main = result["checkin_status"] == "fail"
        if failed_main:
            # 签到失败一律告警。之前只在「续期也失败」时才推，导致签到被拒
            # （例如上游返回「网络故障，请稍后再试」）时完全静默。
            if not ok:
                tail = "该账号需要重新导入凭据。"
                refresh_text = f"失败（{payload}）"
            else:
                tail = "将按排程在当天内自动重试。"
                refresh_text = "成功"
            notify(
                f"【龙湖签到】{acc_name} 失败\n"
                f"续期: {refresh_text}\n签到: {result['checkin_message']}\n{tail}"
            )

    if do_checkin and dx_block:
        # 单独用 conflict 状态：它不是偶发失败，重试没有意义，也不该触发
        # 当天的失败重试排程，否则一天会重复告警 4 次。
        result["checkin_status"] = "conflict"
        result["checkin_message"] = dx_block
        db.update_account(acc_id, last_status="conflict", last_message=dx_block)

    # ---- 3. 刷新资料 ----
    if with_profile:
        try:
            profile = longhu.fetch_profile(account)
            result["profile"] = profile
            db.update_account(
                acc_id,
                growth_value=profile.get("growth_value", 0),
                level_name=profile.get("level_name", ""),
                balance=profile.get("balance", 0),
                nickname=profile.get("nickname", ""),
            )
        except longhu.LonghuError as exc:
            result["error"] = result["error"] or str(exc)
            db.add_log(acc_id, acc_name, "query", "fail", str(exc))

    # last_run_at 只由小程序入口刷新：卡片上的「今日状态」是按这个字段判断
    # 有没有跑过的，APP 入口单独跑时不该改动它。
    if "mini" in wanted:
        db.update_account(acc_id, last_run_at=db.now_iso())

    days = days_left(db.get_account(acc_id).get("expire_at"))
    result["days_left"] = days
    return result


def run_all(do_checkin: bool = True) -> list[dict]:
    accounts = db.list_accounts(only_enabled=True)
    results = []
    for account in accounts:
        try:
            results.append(run_account(account, do_checkin=do_checkin))
        except Exception as exc:  # 单个账号异常不影响其他账号
            logger.exception("[%s] 执行异常", account.get("name"))
            db.add_log(account["id"], account["name"], "run", "fail", f"异常: {exc}")
            results.append({
                "account_id": account["id"], "name": account["name"],
                "checkin_status": "fail", "checkin_message": str(exc), "error": str(exc),
            })
    return results


def daily_summary(results: list[dict]):
    """每日汇总推送：有失败/冲突才提醒，全成功则发一条简报。"""
    if not results:
        return
    failed = [r for r in results if r.get("checkin_status") == "fail"]
    risks = [r for r in results if r.get("checkin_status") == "risk"]
    conflicts = [r for r in results if r.get("checkin_status") == "conflict"]
    ok = [r for r in results if r.get("checkin_status") == "ok"]
    already = [r for r in results if r.get("checkin_status") == "already"]

    # APP 专享签到的结果单独统计：它失败不影响主签到，只作提醒
    app_lines = []
    for item in results:
        for extra in item.get("extra_signs") or []:
            if extra.get("status") in ("fail", "todo", "risk"):
                app_lines.append(f"· {item['name']} {extra['name']}: {extra.get('message')}")

    issues = failed + risks + conflicts
    if issues:
        lines = [f"【龙湖签到】{len(issues)} 个账号需要处理"]
        for item in issues:
            lines.append(f"· {item['name']}: {item.get('checkin_message') or item.get('error')}")
        lines.extend(app_lines)
        notify("\n".join(lines))
    elif ok or app_lines:
        # 全部「今日已签」时原本什么都不推，会导致 APP 入口的手动提醒被吞掉
        text = f"【龙湖签到】成功 {len(ok)} 个，已签 {len(already)} 个"
        if app_lines:
            text += "\n" + "\n".join(app_lines)
        notify(text)
