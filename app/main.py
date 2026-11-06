"""龙湖签到服务：Web 前端 + REST API + 内置定时任务。"""

import logging
import os
from contextlib import asynccontextmanager
from datetime import date
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import db, dxidentity, longhu, parser, runner, scheduler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init()
    scheduler.start()
    logger.info("服务已启动，签到窗口：小程序 %s，APP %s",
                scheduler.window_text("mini"), scheduler.window_text("app"))
    yield


app = FastAPI(title="龙湖签到", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# --------------------------------------------------------------------------
# 页面
# --------------------------------------------------------------------------

@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


# --------------------------------------------------------------------------
# 账号
# --------------------------------------------------------------------------

def _decorate(account: dict, usage: dict[str, list[dict]] | None = None,
              settings: dict | None = None,
              next_runs: dict[str, str] | None = None) -> dict:
    settings = settings if settings is not None else db.get_settings()
    next_runs = next_runs or {}
    item = dict(account)
    for key in ("token", "user_agent", "api_key", "dx_token"):  # 敏感字段不外发
        item.pop(key, None)
    token = account.get("token") or ""
    item["token_mask"] = f"{token[:6]}...{token[-4:]}" if len(token) > 12 else "****"

    # 设备指纹状态。同一指纹用于多个账号会触发风控（2026-11-03 实测），
    # 指纹归 id 最小的账号所有，其余账号会被标记为冲突并暂停签到。
    dx = (account.get("dx_token") or "").strip()
    item["has_dx"] = bool(dx)
    # 只看启用中的账号，与运行时 _dx_conflict 的口径保持一致
    shared = [
        a for a in (usage or {}).get(dx, [])
        if a["id"] != account["id"] and a.get("enabled")
    ] if dx else []
    item["dx_shared"] = bool(shared)
    item["dx_shared_with"] = [a["name"] for a in shared]
    item["dx_conflict"] = any(a["id"] < account["id"] for a in shared)
    item["days_left"] = runner.days_left(account.get("expire_at"))
    # 两个入口各自的窗口：账号自定义优先，否则跟随全局
    item["mini_time"] = (account.get("mini_time") or "").strip()
    item["app_time"] = (account.get("app_time") or "").strip()
    item["windows"] = {
        entry: scheduler.account_window(account, entry, settings)
        for entry in db.SLOT_ENTRIES
    }
    item["next_runs"] = {
        entry: next_runs.get(f"{account['id']}:{entry}", "")
        for entry in db.SLOT_ENTRIES
    }
    return item


@app.get("/api/accounts")
def api_accounts():
    usage = db.dx_usage()
    settings = db.get_settings()
    next_runs = scheduler.next_run_map()
    return [_decorate(acc, usage, settings, next_runs) for acc in db.list_accounts()]


@app.post("/api/accounts/bind")
async def api_bind(
    mode: str = Form(...),
    name: str = Form(""),
    payload: str = Form(""),
    dx_token: str = Form(""),
    file: UploadFile | None = File(None),
):
    if mode == "har":
        if file is None:
            raise HTTPException(400, "HAR 模式需要上传文件")
        raw = await file.read()
    else:
        raw = payload

    try:
        parsed = parser.parse(mode, raw)
    except parser.ParseError as exc:
        raise HTTPException(400, str(exc)) from exc

    account = {
        "token": parsed["token"],
        "user_agent": parsed.get("user_agent") or longhu.DEFAULT_UA,
        "api_key": parsed.get("api_key"),
        "bu_code": parsed.get("bu_code", "C20400"),
        "channel": parsed.get("channel", "C2"),
    }

    # 一账号一指纹：共用指纹会触发风控，提前拦掉，别等跑起来才暴露。
    dx_value = dx_token.strip()
    if dx_value:
        others = db.accounts_with_dx(dx_value)
        if others:
            names = "、".join(a["name"] for a in others)
            raise HTTPException(
                400,
                f"这个指纹已被「{names}」占用。同一指纹用于多个账号会触发风控，"
                "请换一个独立指纹（重装 App 可获取新指纹）。",
            )

    # 校验 token：先直接查资料，失败则尝试续期后重试
    profile = None
    verify_error = ""
    try:
        profile = longhu.probe_token(
            account["token"], account["user_agent"], account["bu_code"], account["channel"]
        )
    except longhu.LonghuError as exc:
        verify_error = str(exc)
        ok, new_token = longhu.refresh_token(account)
        if ok:
            account["token"] = new_token
            try:
                profile = longhu.probe_token(
                    account["token"], account["user_agent"],
                    account["bu_code"], account["channel"],
                )
                verify_error = ""
            except longhu.LonghuError as exc2:
                verify_error = str(exc2)

    if profile is None:
        raise HTTPException(400, f"凭据校验失败：{verify_error or '未知原因'}，请重新抓取")

    # 默认名用脱敏手机号：昵称一律是「珑珠用户」，多账号根本分不出来。
    final_name = (
        (name or "").strip()
        or profile.get("phone")
        or profile.get("nickname")
        or f"龙湖账号 {len(db.list_accounts()) + 1}"
    )

    account_id = db.create_account({
        "name": final_name,
        "token": account["token"],
        "user_agent": account["user_agent"],
        "api_key": account["api_key"],
        "dx_token": dx_value or None,
        "bu_code": account["bu_code"],
        "channel": account["channel"],
        "growth_value": profile.get("growth_value", 0),
        "level_name": profile.get("level_name", ""),
        "balance": profile.get("balance", 0),
        "nickname": profile.get("nickname", ""),
        "expire_at": longhu.expire_at(),
    })
    db.add_log(account_id, final_name, "bind", "ok", f"{parsed['note']}，凭据校验通过")

    return {"ok": True, "id": account_id, "name": final_name, "profile": profile}


@app.post("/api/accounts/{account_id}/dx")
def api_set_dx(account_id: int, dx_token: str = Form("")):
    """补填 App 内真实设备指纹（顶象 token）。"""
    account = db.get_account(account_id)
    if not account:
        raise HTTPException(404, "账号不存在")
    value = dx_token.strip()
    if value and (len(value) < 20 or " " in value):
        raise HTTPException(400, "指纹格式不对，应形如 6ae93a6cUDMfhHgK6eYXWjqtu1qMG9bAJdij8Er1")

    # 一账号一指纹：共用指纹会被上游判成同一设备多账号，直接触发风控。
    if value:
        others = db.accounts_with_dx(value, exclude_id=account_id)
        if others:
            names = "、".join(a["name"] for a in others)
            raise HTTPException(
                400,
                f"这个指纹已被「{names}」占用。同一指纹用于多个账号会触发风控，"
                "请换一个独立指纹（重装 App 可获取新指纹）。",
            )

    db.update_account(account_id, dx_token=value or None)
    db.add_log(account_id, account["name"], "dx",
               "ok" if value else "fail", "已保存设备指纹" if value else "已清除设备指纹")
    return {"ok": True, "has_dx": bool(value)}


@app.post("/api/accounts/{account_id}/dx/prepare")
def api_dx_prepare(account_id: int):
    """第一步：服务端按账号 token 生成一份新指纹，等浏览器过滑块激活。

    生成不需要浏览器（纯标准库派生），激活必须在用户浏览器里跑顶象 SDK，
    所以拆成 prepare/commit 两步：这一步只造指纹并暂存 10 分钟。
    """
    account = db.get_account(account_id)
    if not account:
        raise HTTPException(404, "账号不存在")

    fingerprint, message = dxidentity.generate(account)
    if not fingerprint:
        db.add_log(account_id, account["name"], "dx", "fail", f"生成指纹失败：{message}")
        return {"ok": False, "message": message}

    dxidentity.put_pending(account_id, fingerprint)
    logger.info("[%s] 已生成待激活指纹: %s", account["name"], message)
    return {
        "ok": True,
        "fingerprint": fingerprint,
        "message": message,
        "has_dx": bool((account.get("dx_token") or "").strip()),
    }


@app.post("/api/accounts/{account_id}/dx/commit")
def api_dx_commit(account_id: int, fingerprint: str = Form(""),
                  captcha_token: str = Form("")):
    """第二步：浏览器过完滑块，把（已绑定滑块 token 的）指纹落库。"""
    account = db.get_account(account_id)
    if not account:
        raise HTTPException(404, "账号不存在")

    value = fingerprint.strip()
    captcha = captcha_token.strip()
    if not value or not captcha:
        raise HTTPException(400, "缺少指纹或激活凭据（滑块没通过？）")

    # 只接受 prepare 阶段发出去的那一份，防止前端乱传
    pending = dxidentity.take_pending(account_id)
    if pending != value:
        raise HTTPException(400, "指纹已过期，请重新点一次「重置指纹」")

    others = db.accounts_with_dx(value, exclude_id=account_id)
    if others:
        names = "、".join(a["name"] for a in others)
        raise HTTPException(400, f"这个指纹已被「{names}」占用，请重新生成")

    db.update_account(account_id, dx_token=value)
    dxidentity.drop_pending(account_id)
    db.add_log(account_id, account["name"], "dx", "ok", "已重置并激活设备指纹")
    return {"ok": True, "has_dx": True}


@app.delete("/api/accounts/{account_id}")
def api_delete(account_id: int):
    if not db.get_account(account_id):
        raise HTTPException(404, "账号不存在")
    db.delete_account(account_id)
    return {"ok": True}


@app.post("/api/accounts/{account_id}/run")
def api_run(account_id: int, app: str | None = None):
    """立即跑一轮。app=auto 强制尝试 APP 入口，app=off 跳过，默认按设置。"""
    account = db.get_account(account_id)
    if not account:
        raise HTTPException(404, "账号不存在")
    mode = (app or "").strip().lower() or None
    if mode and mode not in runner.APP_MODES:
        raise HTTPException(400, "app 只能是 auto / manual / off")
    result = runner.run_account(account, do_checkin=True, app_mode=mode)
    return result


@app.get("/api/accounts/{account_id}/logs")
def api_account_logs(account_id: int, limit: int = 20):
    return db.list_logs(account_id, limit)


# --------------------------------------------------------------------------
# 概览 / 设置 / 日志
# --------------------------------------------------------------------------

@app.get("/api/overview")
def api_overview():
    accounts = db.list_accounts()
    today = date.today().isoformat()
    stats = {"ok": 0, "already": 0, "fail": 0, "pending": 0, "conflict": 0, "risk": 0}
    min_days = None

    for acc in accounts:
        days = runner.days_left(acc.get("expire_at"))
        if days is not None:
            min_days = days if min_days is None else min(min_days, days)
        ran_today = (acc.get("last_run_at") or "")[:10] == today
        if not acc.get("enabled"):
            stats["pending"] += 1
        elif not ran_today:
            stats["pending"] += 1
        else:
            status = acc.get("last_status") or ""
            stats[status if status in stats else "fail"] += 1

    settings = db.get_settings()
    return {
        "total": len(accounts),
        "stats": stats,
        "min_days": min_days,
        "next_run": scheduler.next_run_text(),
        "checkin_time": settings.get("checkin_time", "08:00"),
        "app_checkin_time": settings.get("app_checkin_time", "09:30"),
        "window": scheduler.window_text("mini"),
        "app_window": scheduler.window_text("app"),
    }


@app.get("/api/logs")
def api_logs(limit: int = 50):
    return db.list_logs(None, limit)


@app.get("/api/settings")
def api_get_settings():
    data = db.get_settings()
    return {
        "checkin_time": data.get("checkin_time", "08:00"),
        "checkin_jitter": data.get("checkin_jitter", "60"),
        "app_checkin_time": data.get("app_checkin_time", "09:30"),
        "app_checkin_jitter": data.get("app_checkin_jitter", "60"),
        "window": scheduler.window_text("mini"),
        "app_window": scheduler.window_text("app"),
        "webhook_url": data.get("webhook_url", ""),
        "app_checkin_mode": data.get("app_checkin_mode", "manual"),
        "next_run": scheduler.next_run_text(),
    }


def _parse_time_field(value: str, label: str) -> str:
    try:
        hour, minute = value.strip().split(":")
        assert 0 <= int(hour) <= 23 and 0 <= int(minute) <= 59
    except Exception:
        raise HTTPException(400, f"{label}格式应为 HH:MM") from None
    return f"{int(hour):02d}:{int(minute):02d}"


def _check_gap(mini_time: str, app_time: str):
    """两个入口不要设成同一时刻——分时签到就是为了不连着打。"""
    def minutes(text: str) -> int:
        hour, minute = text.split(":")
        return int(hour) * 60 + int(minute)

    diff = abs(minutes(mini_time) - minutes(app_time))
    if min(diff, 1440 - diff) < 5:
        raise HTTPException(
            400,
            "小程序和 APP 的时间至少错开 5 分钟——两个入口同一时刻连着打，"
            "等于没有分开排期。",
        )


@app.post("/api/settings")
def api_save_settings(
    checkin_time: str = Form(...),
    webhook_url: str = Form(""),
    checkin_jitter: str | None = Form(None),
    app_checkin_time: str | None = Form(None),
    app_checkin_jitter: str | None = Form(None),
    app_checkin_mode: str | None = Form(None),
):
    mini_time = _parse_time_field(checkin_time, "小程序时间")
    app_time = _parse_time_field(app_checkin_time or db.get_settings().get("app_checkin_time", "09:30"),
                                 "APP 时间")
    _check_gap(mini_time, app_time)

    values = {"checkin_time": mini_time, "webhook_url": webhook_url.strip(),
              "app_checkin_time": app_time}
    for field, key, label in ((checkin_jitter, "checkin_jitter", "随机浮动"),
                              (app_checkin_jitter, "app_checkin_jitter", "APP 随机浮动")):
        if field is None or field.strip() == "":
            continue
        try:
            jitter = int(float(field))
            assert 0 <= jitter <= 1439
        except Exception:
            raise HTTPException(400, f"{label}应为 0–1439 之间的分钟数") from None
        values[key] = str(jitter)

    if app_checkin_mode is not None and app_checkin_mode.strip() != "":
        mode = app_checkin_mode.strip().lower()
        if mode not in runner.APP_MODES:
            raise HTTPException(400, "APP 入口方式只能是 auto / manual / off")
        values["app_checkin_mode"] = mode

    db.save_settings(values)
    scheduler.reschedule()
    return {
        "ok": True,
        "window": scheduler.window_text("mini"),
        "app_window": scheduler.window_text("app"),
        "next_run": scheduler.next_run_text(),
    }


@app.post("/api/accounts/{account_id}/schedule")
def api_set_schedule(account_id: int, mini_time: str = Form(""),
                     app_time: str = Form("")):
    """单账号自定义两个入口的时间。留空表示跟随全局设置。"""
    account = db.get_account(account_id)
    if not account:
        raise HTTPException(404, "账号不存在")

    mini_value = _parse_time_field(mini_time, "小程序时间") if mini_time.strip() else ""
    app_value = _parse_time_field(app_time, "APP 时间") if app_time.strip() else ""

    settings = db.get_settings()
    effective = dict(account, mini_time=mini_value, app_time=app_value)
    _check_gap(
        scheduler.effective_start(effective, "mini", settings),
        scheduler.effective_start(effective, "app", settings),
    )

    db.update_account(account_id, mini_time=mini_value or None, app_time=app_value or None)
    for entry in db.SLOT_ENTRIES:
        db.clear_slot_plan(account_id, entry)
    scheduler.reschedule()
    db.add_log(account_id, account["name"], "schedule", "ok",
               f"签到时间已更新：小程序 {mini_value or '跟随全局'}，"
               f"APP {app_value or '跟随全局'}")
    return {"ok": True}


@app.get("/api/health")
def api_health():
    return {"ok": True, "data_dir": os.environ.get("DATA_DIR", "./data")}
