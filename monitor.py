#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
钟山烟语 · 礼品兑换商品补货监控（可用性口径版）
====================================================
鉴权：Bearer access_token + Content-Steam（RSA 加密的「设备号&平台&时间戳&UA」签名）

关键结论（决定监控口径）：
    detail 接口的 usableSkuHitNums 只是平台「可兑额度」，几乎恒为 9500~10000，
    不代表真实可兑状态。真实能否兑换以「订单确认页」返回为准：
        goods-order/v1/getconfirmdata -> skuVOList[].message
        message 含「缺货」= 该收货地址当前无法兑换（供应商实际库存/区域无货所致）

动作：
    --scan    扫商品池（分类清单），记录在售商品、乾币、上架时间、分类
    --stock   对关注商品逐个走确认页，判定有货/缺货，产出补货报告
"""

import argparse
try:
    import fcntl          # Linux/Mac 单实例锁；Windows 没有这个模块
    _HAS_FCNTL = True
except ImportError:
    fcntl = None
    _HAS_FCNTL = False
import base64
import csv
import json
import os
import random
import sys
import time
import uuid
from datetime import datetime

import requests
import struct

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
POOL_PATH = os.path.join(BASE_DIR, "state", "sku_pool.json")
STOCK_PATH = os.path.join(BASE_DIR, "state", "avail_snapshot.json")
LOG_CSV = os.path.join(BASE_DIR, "data", "stock_log.csv")
REPORT_DIR = os.path.join(BASE_DIR, "reports")

API = "https://api.jszyshop.com/front"

UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 "
      "(KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.49 NetType/WIFI Language/zh_CN")

PK = ("MIGJAoGBAMWlSwwUW3x1F9s6QdWlo3g/Gny9gZTTpCnBvtV9UqZlXqY3YlBPvCJPPggjt6hrdoQIN/"
      "xVpSa9fJc2RG8i3Lp0916LEQHmKMJqAK1xhOCJmgCPVPl+yezJuKkK68j9V3FHOz8VJTg33c8DJGc"
      "MWwO5ldA9NHjyUDsfrAmE92xPAgMBAAE=")
_KEY_B64 = PK  # 只保留 base64 文本，密钥由 _rsa_pub() 纯 Python 解析

CATEGORIES = [
    ("GOODS_CATEGORY_001", "家居日用"),
    ("GOODS_CATEGORY_004", "家用电器"),
    ("GOODS_CATEGORY_005", "箱包运动"),
    ("GOODS_CATEGORY_006", "智能数码"),
    ("GOODS_CATEGORY_007", "个护清洁"),
    ("GOODS_CATEGORY_099", "其他"),
]

ST_OK, ST_OUT, ST_OFF, ST_UNK = "可兑换", "缺货", "已下架", "待核实"

_DEVICE_ID = None


def log(m):
    print("[%s] %s" % (datetime.now().strftime("%H:%M:%S"), m), flush=True)


def load_json(p, default):
    if not os.path.exists(p):
        return default
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def dump_json(p, obj):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


_DEVICE_OVERRIDE = ""


def set_device_override(did):
    """多账号时，每个账号必须用自己固定的设备号，否则 token 会被判多设备作废"""
    global _DEVICE_OVERRIDE
    _DEVICE_OVERRIDE = (did or "").strip()


def device_id():
    """固定设备号，避免同一 token 被识别为多设备而作废"""
    global _DEVICE_ID
    if _DEVICE_OVERRIDE:
        return _DEVICE_OVERRIDE
    if _DEVICE_ID:
        return _DEVICE_ID
    cfg = load_json(CONFIG_PATH, {})
    did = (cfg.get("device_id") or "").strip()
    if not did:
        did = uuid.uuid4().hex
        cfg["device_id"] = did
        dump_json(CONFIG_PATH, cfg)
    _DEVICE_ID = did
    return did


def _rsa_pub():
    """纯 Python 解析 PKCS#1 DER 公钥，返回 (n, e, key_size)。免去 pycryptodome 依赖，手机/无编译环境也能跑。"""
    der = base64.b64decode(_KEY_B64)
    # SEQUENCE { INTEGER n, INTEGER e }
    def _read_len(b, i):
        l = b[i]
        if l & 0x80:
            n = l & 0x7f
            return int.from_bytes(b[i + 1:i + 1 + n], "big"), i + 1 + n
        return l, i + 1
    i = 1
    if der[0] != 0x30:
        raise ValueError("非 SEQUENCE")
    _, i = _read_len(der, i)
    if der[i] != 0x02:
        raise ValueError("缺少模数")
    i += 1
    ln, i = _read_len(der, i)
    n = int.from_bytes(der[i:i + ln], "big")
    i += ln
    if der[i] != 0x02:
        raise ValueError("缺少指数")
    i += 1
    ln_e, i = _read_len(der, i)
    e = int.from_bytes(der[i:i + ln_e], "big")
    return n, e, (n.bit_length() + 7) // 8


_N, _E, _KEY_SIZE = _rsa_pub()
_CHUNK = _KEY_SIZE - 11


def _pkcs1_encrypt(chunk):
    """PKCS#1 v1.5 加密一块：0x00 || 0x02 || 非零随机填充 || 0x00 || 明文"""
    pad_len = _KEY_SIZE - len(chunk) - 3
    pad = bytes(random.randint(1, 255) for _ in range(pad_len))
    em = b"\x00\x02" + pad + b"\x00" + chunk
    m = int.from_bytes(em, "big")
    c = pow(m, _E, _N)
    return c.to_bytes(_KEY_SIZE, "big")


def steam_header():
    ts = str(int(time.time() * 1000))
    text = "%s&ios&%s&%s" % (device_id(), ts, UA)
    raw = text.encode()
    buf = b""
    for i in range(0, len(raw), _CHUNK):
        buf += _pkcs1_encrypt(raw[i:i + _CHUNK])
    return base64.b64encode(buf).decode()


OAUTH_URL = "https://api.jszyshop.com/front/oauth/token"
CLIENT_ID = "zsyy-client"
CLIENT_SECRET = "4XeYEUQE6"


def refresh_access_token(cfg):
    """用 refresh_token 换新 access_token（前端 10004 时走的就是这条链路）"""
    rt = (cfg.get("refresh_token") or "").strip()
    if not rt:
        raise ApiError("NO_REFRESH", "缺少 refresh_token，请在微信里重新登录后复制 cookie 里的 refresh_token")
    payload = {
        "grant_type": "refresh_token",
        "refresh_token": rt,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        "User-Agent": UA,
        "Origin": "https://m.jszyshop.com",
        "Referer": "https://m.jszyshop.com/",
    }
    r = requests.post(OAUTH_URL, data=payload, headers=headers, timeout=20)
    try:
        j = r.json()
    except Exception:
        raise ApiError("REFRESH_BAD", "续期返回非 JSON：%s" % r.text[:120])
    data = j.get("respData") if isinstance(j.get("respData"), dict) else j
    at = data.get("access_token")
    if not at:
        raise ApiError("REFRESH_FAIL", "续期失败：%s" % (j.get("error_description") or j.get("respMsg") or j))
    cfg["access_token"] = at
    if data.get("refresh_token"):
        cfg["refresh_token"] = data["refresh_token"]
    if data.get("expires_in"):
        cfg["token_expires_at"] = int(time.time()) + int(data["expires_in"])
    if data.get("uuid"):
        cfg["uuid"] = data["uuid"]
    dump_json(CONFIG_PATH, cfg)
    return at


class ApiError(Exception):
    def __init__(self, code, msg):
        self.code, self.msg = code, msg
        super().__init__("%s %s" % (code, msg))


def api_post(path, params, token, retry=3):
    url = API + path
    refreshed = 0
    for attempt in range(retry):
        headers = {
            "Authorization": "Bearer " + token,
            "Content-Steam": steam_header(),
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            "User-Agent": UA,
            "Origin": "https://m.jszyshop.com",
            "Referer": "https://m.jszyshop.com/goods",
        }
        try:
            r = requests.post(url, data=params, headers=headers, timeout=20)
            j = r.json()
        except Exception as e:
            if attempt == retry - 1:
                raise ApiError("NETWORK", str(e))
            time.sleep(1.5 * (attempt + 1))
            continue
        code = str(j.get("respCode") or "")
        if code in ("00000", "0", ""):
            return j.get("respData")
        if code == "10004":
            # 续期后偶尔仍会被判失效（服务端生效有延迟/并发续期互相顶掉），给两次机会并稍等再试
            if refreshed < 2 and (load_json(CONFIG_PATH, {}).get("refresh_token") or "").strip():
                try:
                    new_token = refresh_access_token(load_json(CONFIG_PATH, {}))
                    token = new_token
                    refreshed += 1
                    log("  access_token 已自动续期")
                    time.sleep(0.8)
                    continue
                except ApiError as re_:
                    raise ApiError(code, "登录凭证已失效，自动续期也失败（%s）" % re_.msg)
            raise ApiError(code, "登录凭证已失效")
        if code == "10006":
            raise ApiError(code, "账号被风控限制")
        if code == "10023":
            raise ApiError(code, "商城系统维护中")
        if code in ("10013", "10008"):
            raise ApiError(code, j.get("respMsg"))
        if attempt == retry - 1:
            raise ApiError(code, j.get("respMsg"))
        time.sleep(1.2 * (attempt + 1))
    raise ApiError("UNKNOWN", "重试耗尽")


# ------------------------------------------------------------------ 地址
def default_recv(token, cfg):
    rid = (cfg.get("recv_id") or "").strip()
    if rid:
        return rid
    data = api_post("/goods-sku/v1/getaddrlist", {}, token)
    if isinstance(data, list) and data:
        for a in data:
            if a.get("recvDeft"):
                rid = a.get("recvId")
                break
        rid = rid or data[0].get("recvId")
    if not rid:
        raise ApiError("NO_ADDR", "账号下没有收货地址，无法判定区域是否有货")
    cfg["recv_id"] = rid
    dump_json(CONFIG_PATH, cfg)
    return rid


# ------------------------------------------------------------------ 商品池
def scan_pool(token, max_pages=80, sleep=0.25):
    pool = {}
    for code, name in CATEGORIES:
        page, pages = 1, 1
        while page <= min(pages, max_pages):
            data = api_post("/sku/v1/category/getcardlist", {
                "zsyyGoodsCategory": code,
                "skuCoinsSort": "SKU_COINS_ALL",
                "skuTimeSort": "OPER_TIME_ALL",
                "pageNum": page,
            }, token)
            if not isinstance(data, dict):
                break
            pages = int(data.get("pages") or 0) or pages
            for r in data.get("records") or []:
                sid = str(r.get("chnlSkuId") or "")
                if sid:
                    pool[sid] = {"id": sid, "name": r.get("chnlSkuName") or "",
                                 "coins": r.get("chnlSkuCoins"),
                                 "img": r.get("chnlSkuImg1") or "",
                                 "operTime": r.get("operTime") or "",
                                 "category": name}
            log("  %s 第 %d/%d 页，累计 %d 件" % (name, page, pages, len(pool)))
            page += 1
            if page <= pages:
                time.sleep(sleep + random.uniform(0, 0.1))
    return pool


# ------------------------------------------------------------------ 可用性
def check_avail(sid, token, recv_id, nums=1):
    """走订单确认页判定真实可兑状态"""
    body = json.dumps([{"chnlSkuId": str(sid), "chnlSkuNums": nums}], ensure_ascii=False)
    data = api_post("/goods-order/v1/getconfirmdata",
                    {"recvId": recv_id, "orderConfirmBOStr": body}, token)
    if not isinstance(data, dict):
        return None
    items = data.get("skuVOList") or []
    if not items:
        return None
    it = items[0]
    msg = (it.get("message") or "").strip()
    if "缺货" in msg or "无货" in msg:
        st = ST_OUT
    elif "下架" in msg or "不可兑换" in msg:
        st = ST_OFF
    elif msg:
        st = ST_UNK
    else:
        st = ST_OK
    return {"id": str(sid), "name": it.get("chnlSkuName") or "",
            "coins": it.get("chnlSkuCoins"), "msg": msg, "state": st}


def fetch_quota(sid, token):
    """平台可兑额度（usableSkuHitNums）。注意：这是平台配置的可兑上限，随兑换递减，
    不是仓储实物库存；接口不暴露供应商真实库存数量。"""
    d = api_post("/goods-sku/v1/getinfo", {"chnlSkuId": str(sid)}, token)
    if not isinstance(d, dict):
        return None
    return d.get("usableSkuHitNums")


PUSHPLUS_URL = "http://www.pushplus.plus/send"


def push_wechat(cfg, title, content):
    """推送通知。

    渠道由 config.json 的 push_channels 控制（默认 ["wechat"]）：
      wechat / mail / webhook / cp / sms / voice —— 都是 PushPlus 的通道
    多用户：pushplus_token + pushplus_tokens 列表
    群组一对多：pushplus_topic
    邮件通道的收件地址，是 PushPlus 后台绑定的邮箱；也可用 email_to 直传
    """
    tokens = []
    if cfg.get("pushplus_token"):
        tokens.append(str(cfg["pushplus_token"]).strip())
    for t in (cfg.get("pushplus_tokens") or []):
        t = str(t).strip()
        if t and t not in tokens:
            tokens.append(t)
    if not tokens:
        return False, "未配置 pushplus_token"

    channels = [str(c).strip() for c in (cfg.get("push_channels") or ["wechat"]) if str(c).strip()]
    # 群组可配多个：pushplus_topic（单个）+ pushplus_topics（列表），去重保序
    topics = []
    if cfg.get("pushplus_topic"):
        topics.append(str(cfg["pushplus_topic"]).strip())
    for t in (cfg.get("pushplus_topics") or []):
        t = str(t).strip()
        if t and t not in topics:
            topics.append(t)
    topics = [t for t in topics if t]

    ok_list, fail_list = [], []
    for tk in tokens:
        for ch in channels:
            payload = {"token": tk, "title": title, "content": content,
                       "template": "html", "channel": ch}
            if ch == "mail" and cfg.get("email_to"):
                payload["to"] = cfg["email_to"]
            # wechat 渠道：有群组就逐个群组推，没有就推给自己
            sends = [dict(payload, topic=t) for t in topics] if (ch == "wechat" and topics) else [payload]
            for i, body in enumerate(sends):
                tag = "%s/%s" % (tk[-6:], ch)
                if ch == "wechat" and topics:
                    tag = "%s/%s/%s" % (tk[-6:], ch, topics[i])
                try:
                    r = requests.post(PUSHPLUS_URL, json=body, timeout=15)
                    j = r.json()
                    if int(j.get("code") or 0) == 200:
                        ok_list.append(tag)
                    else:
                        fail_list.append("%s:%s" % (tag, j.get("msg")))
                except Exception as e:
                    fail_list.append("%s:%s" % (tag, e))

    if fail_list:
        return (bool(ok_list),
                "成功 %d（%s），失败 %d（%s）"
                % (len(ok_list), ",".join(ok_list), len(fail_list), "; ".join(fail_list)))
    return True, "已推送（%s）" % ",".join(ok_list)


def format_push(changes, cur, run_time, moves=None):
    moves = moves or []
    """每轮都推当前状态：先列各商品状态，再列本轮变动"""
    ok = sum(1 for c in cur if c["state"] == ST_OK)
    out = sum(1 for c in cur if c["state"] == ST_OUT)
    head = "<p><b>%s</b></p><p>可兑换 %d 件 ｜ 缺货 %d 件</p>" % (run_time, ok, out)
    head += "<hr/>"
    order = {ST_OK: 0, ST_OUT: 1, ST_UNK: 2, ST_OFF: 3}
    for c in sorted(cur, key=lambda x: order.get(x["state"], 9)):
        color = "#16a34a" if c["state"] == ST_OK else "#dc2626"
        head += ('<p><b>%s</b><br/><span style="color:%s"><b>%s</b></span>'
                 ' ｜ %s 乾币</p>'
                 % (c["name"], color, c["state"], c.get("coins")))
    if changes:
        head += "<hr/><p><b>状态变动</b></p>"
        for t, c, note in changes:
            head += "<p>【%s】%s —— %s</p>" % (t, c["name"], note)
    return head


RESTOCK_TYPES = ("补货", "重新上架")


def in_quiet_hours(cfg, now=None):
    """免打扰时段：默认 00:00-08:00 不推送（照常采集记账）"""
    q = cfg.get("quiet_hours") or ["00:00", "08:00"]
    try:
        start, end = q[0], q[1]
    except Exception:
        return False
    now = now or datetime.now()
    hm = now.strftime("%H:%M")
    if start <= end:
        return start <= hm < end
    return hm >= start or hm < end


def in_quiet_hours(cfg, now=None):
    """免打扰时段（默认 0:00-08:00），时段内不推送任何消息"""
    now = now or datetime.now()
    start = int(cfg.get("quiet_start_hour", 0))
    end = int(cfg.get("quiet_end_hour", 8))
    h = now.hour
    if start == end:
        return False
    if start < end:
        return start <= h < end
    return h >= start or h < end          # 跨零点的情况


def format_restock(changes, cur, run_time):
    """补货专属通知：把补货的挑出来，放在最前面"""
    hits = [x for x in changes if x[0] in RESTOCK_TYPES]
    body = '<p style="color:#dc2626"><b>本轮有 %d 件补货，速去兑换！</b></p>' % len(hits)
    for t, c, note in hits:
        body += ('<p><b>%s</b><br/><span style="color:#dc2626"><b>%s</b></span> ｜ '
                 '%s 乾币</p>'
                 % (c["name"], c["state"], c.get("coins")))
    others = [c for c in cur if c["state"] != ST_OK]
    if others:
        body += "<hr/><p>其余商品：%s</p>" % "、".join(
            "%s（%s）" % (c["name"], c["state"]) for c in others)
    body += "<p>%s</p>" % run_time
    return body


# ------------------------------------------------------------------ 比对
def quota_trend(prev, cur):
    """额度变化：返回 {id: (上次值, 本次值, 差值)}"""
    prev_map = {x["id"]: x for x in prev}
    out = {}
    for c in cur:
        p = prev_map.get(c["id"])
        if p and p.get("quota") is not None and c.get("quota") is not None:
            d = int(c["quota"]) - int(p["quota"])
            if d:
                out[c["id"]] = (int(p["quota"]), int(c["quota"]), d)
    return out


def stock_moves(prev, cur, threshold=1):
    """商城库存量（usableSkuHitNums）变动，返回 [{id,name,old,new,delta}]"""
    prev_map = {x["id"]: x for x in prev}
    out = []
    for c in cur:
        p = prev_map.get(c["id"])
        if not p:
            continue
        o, n = p.get("stock"), c.get("stock")
        if o is None or n is None:
            continue
        d = int(n) - int(o)
        if abs(d) >= threshold:
            out.append({"id": c["id"], "name": c["name"], "old": int(o),
                        "new": int(n), "delta": d})
    out.sort(key=lambda x: -abs(x["delta"]))
    return out


def diff(prev, cur):
    changes = []
    prev_map = {x["id"]: x for x in prev}
    for c in cur:
        p = prev_map.get(c["id"])
        if not p:
            changes.append(("纳入监控", c, "首次采集，当前：%s" % c["state"]))
            continue
        if p["state"] == c["state"]:
            continue
        if p["state"] == ST_OUT and c["state"] == ST_OK:
            changes.append(("补货", c, "缺货 → 可兑换（可以抢了）"))
        elif p["state"] == ST_OK and c["state"] == ST_OUT:
            changes.append(("变缺货", c, "可兑换 → 缺货"))
        elif p["state"] == ST_OFF and c["state"] == ST_OK:
            changes.append(("重新上架", c, "已下架 → 可兑换"))
        elif c["state"] == ST_OFF:
            changes.append(("下架", c, "%s → 已下架" % p["state"]))
        else:
            changes.append(("状态变化", c, "%s → %s" % (p["state"], c["state"])))
    for pid, p in prev_map.items():
        if all(pid != c["id"] for c in cur):
            changes.append(("失联", p, "本轮未取到该商品状态"))
    return changes


def write_ledger(cur, run_time):
    os.makedirs(os.path.dirname(LOG_CSV), exist_ok=True)
    new = not os.path.exists(LOG_CSV)
    with open(LOG_CSV, "a", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["采集时间", "商品ID", "商品名称", "所需乾币", "可兑状态", "平台提示"])
        for c in cur:
            w.writerow([run_time, c["id"], c["name"], c.get("coins"), c["state"], c["msg"]])


def build_report(cur, changes, run_time, recv_id, trends=None):
    trends = trends or {}
    L = ["# 钟山烟语 · 补货监控（可用性口径）", "",
         "- 采集时间：%s" % run_time,
         "- 收货地址 ID：%s（缺货判定按此地址的供应商实际库存）" % recv_id,
         "- 监控商品：%d 件" % len(cur), ""]
    cnt = {}
    for t, _, _ in changes:
        cnt[t] = cnt.get(t, 0) + 1
    L.append("**本次结论**：可兑换 %d 件 ｜ 缺货 %d 件"
             % (sum(1 for c in cur if c["state"] == ST_OK),
                sum(1 for c in cur if c["state"] == ST_OUT)))
    L.append("")
    L.append("## 一、变动")
    L.append("")
    if changes:
        L.append("| 类型 | 商品 | 乾币 | 说明 |")
        L.append("|---|---|---|---|")
        for t, c, note in changes:
            L.append("| %s | %s | %s | %s |" % (t, c["name"], c.get("coins"), note))
    else:
        L.append("本次无变动。")
    L.append("")
    L.append("## 二、当前状态")
    L.append("")
    L.append("| 商品 | 乾币 | 状态 | 平台提示 |")
    L.append("|---|---|---|---|")
    for c in sorted(cur, key=lambda x: x["state"]):
        L.append("| %s | %s | **%s** | %s |"
                 % (c["name"], c.get("coins"), c["state"], c["msg"] or "—"))
    L.append("")
    L.append("---")
    L.append("_可兑状态：订单确认页 goods-order/v1/getconfirmdata 的 skuVOList[].message（按收货地址判定真实能否兑换）_")
    L.append("")
    return "\n".join(L)


def save_report(md, run_time):
    os.makedirs(REPORT_DIR, exist_ok=True)
    stamp = run_time.replace(":", "").replace("-", "").replace(" ", "_")
    p = os.path.join(REPORT_DIR, "report_%s.md" % stamp)
    open(p, "w", encoding="utf-8").write(md)
    open(os.path.join(REPORT_DIR, "latest.md"), "w", encoding="utf-8").write(md)
    return p


# ------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan", action="store_true", help="重建商品池（全部分类）")
    ap.add_argument("--stock", action="store_true", help="查关注商品可兑状态")
    ap.add_argument("--ids", help="临时指定商品ID，逗号分隔")
    ap.add_argument("--no-push", action="store_true", help="只出报告，不推微信")
    ap.add_argument("--force-push", action="store_true", help="忽略免打扰时段强制推送")
    ap.add_argument("--account", help="使用 config.json 里 accounts 中的哪个账号（默认 active_account）")
    ap.add_argument("--restock-only", action="store_true",
                    help="只在出现补货/重新上架时推送（用于高频补货哨兵）")
    args = ap.parse_args()

    cfg = load_json(CONFIG_PATH, {})

    # 多账号：accounts 里每个账号有各自的 refresh_token 与固定 device_id
    accounts = cfg.get("accounts") or {}
    acct_name = getattr(args, "account", None) or cfg.get("active_account") or ""
    if acct_name and acct_name in accounts:
        a = accounts[acct_name] or {}
        if a.get("refresh_token"):
            cfg["refresh_token"] = a["refresh_token"]
        if a.get("access_token"):
            cfg["access_token"] = a["access_token"]
        if a.get("device_id"):
            set_device_override(a["device_id"])
        log("使用账号：%s" % acct_name)

    token = (cfg.get("access_token") or "").strip()
    if not token:
        print("!! 缺少 access_token")
        return 2

    pool = load_json(POOL_PATH, {}).get("skus", {})
    run_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        if args.scan:
            log("扫描商品池…")
            new = scan_pool(token)
            dump_json(POOL_PATH, {"time": run_time, "count": len(new), "skus": new})
            log("商品池：%d 件" % len(new))
            pool = new
        if not args.stock:
            return 0

        ids = [x.strip() for x in (args.ids or "").split(",") if x.strip()] \
            or [str(x) for x in (cfg.get("watch_ids") or [])]
        if not ids:
            print("!! config.json 的 watch_ids 为空")
            return 1

        log("配置已加载，正在取默认收货地址…")
        recv_id = default_recv(token, cfg)
        log("判定地址：%s ｜ 待查 %d 件" % (recv_id, len(ids)))

        cur = []
        prev0 = load_json(STOCK_PATH, {}).get("goods", [])
        ids_set = set(str(x) for x in ids)
        for i, sid in enumerate(ids, 1):
            try:
                d = check_avail(sid, token, recv_id)
            except ApiError as e:
                log("  商品 %s 查询失败：%s" % (sid, e))
                if e.code == "10023":
                    print("!! 商城系统维护中（10023），本轮跳过，不写快照以免误判")
                    return 3
                if e.code in ("10004", "10006"):
                    break
                continue
            if not d:
                continue
            try:
                info = api_post("/goods-sku/v1/getinfo", {"chnlSkuId": sid}, token)
                d["stock"] = (info or {}).get("usableSkuHitNums")
            except ApiError:
                d["stock"] = None
            meta = pool.get(sid) or {}
            d["category"] = meta.get("category")
            cur.append(d)
            log("  %d/%d %s → %s" % (i, len(ids), d["name"][:24], d["state"]))
            time.sleep(0.25 + random.uniform(0, 0.1))

        # 本轮有个别商品没取到：用上一轮快照补位，既不误报「失联」，也不写残快照
        got_ids = {c["id"] for c in cur}
        for p_item in prev0:
            if p_item["id"] not in got_ids and p_item["id"] in ids_set:
                cur.append(p_item)
    except ApiError as e:
        print("!! 接口异常：%s %s" % (e.code, e.msg))
        if e.code == "10004":
            print("   凭证失效，请在微信重新抓一次 Authorization 发我。")
        return 2

    prev = load_json(STOCK_PATH, {}).get("goods", [])
    changes = diff(prev, cur)
    trends = quota_trend(prev, cur)
    md = build_report(cur, changes, run_time, recv_id, trends)
    path = save_report(md, run_time)
    write_ledger(cur, run_time)
    dump_json(STOCK_PATH, {"time": run_time, "count": len(cur), "goods": cur})

    cfg_now = load_json(CONFIG_PATH, {})
    mv = stock_moves(prev, cur, int(cfg_now.get("stock_delta_threshold") or 1))
    hits = [x for x in changes if x[0] in RESTOCK_TYPES]

    quiet = in_quiet_hours(cfg_now) and not args.force_push
    if quiet:
        print("免打扰时段（%02d:00-%02d:00），本轮不推送" % (
            int(cfg_now.get("quiet_start_hour", 0)), int(cfg_now.get("quiet_end_hour", 8))))

    if not args.no_push and hits and not quiet:
        ok, info = push_wechat(cfg_now, "🔔 补货通知：%d 件商品可兑换了" % len(hits),
                               format_restock(changes, cur, run_time))
        print("补货通知：" + info)

    if not args.restock_only and not args.no_push and not quiet:
        mode = (cfg_now.get("push_mode") or "always").strip()
        # 只有真实状态变动才推：取数失败（失联）不算变动，免得误报
        push_changes = [c for c in changes if c[0] != "失联"]
        if mode == "restock":
            # 只在有货时提醒：缺货、下架一律不推；
            # 有货时上一条「补货通知」已经发过，这里不再重复发状态播报
            push_changes = []
        if mode == "always" or bool(push_changes):
            title = ("钟山烟语补货提醒（%d 条变动）" % len(push_changes)) if push_changes \
                else "钟山烟语状态播报（无变动）"
            ok, info = push_wechat(cfg_now, title, format_push(push_changes, cur, run_time, mv))
            print("推送：" + info)


    print("=" * 58)
    print("%s ｜ %d 件 ｜ 变动 %d 条" % (run_time, len(cur), len(changes)))
    for t, c, note in changes:
        print("  [%s] %s — %s" % (t, c["name"][:26], note))
    print("报告：%s" % path)
    print("=" * 58)
    return 0


def _acquire_run_lock(timeout=120):
    """同一时刻只允许一个 monitor 进程在跑：常驻轮询和定时任务容易撞车，
    两个进程同时续期会互相把 access_token 顶掉，表现就是轮换着报 10004。"""
    lock_path = os.path.join(BASE_DIR, "state", ".monitor.lock")
    os.makedirs(os.path.dirname(lock_path), exist_ok=True)
    f = open(lock_path, "w")
    if not _HAS_FCNTL:
        return f          # Windows 下不做跨进程锁，交给「只开一个窗口」来保证
    deadline = time.time() + timeout
    while True:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return f
        except (BlockingIOError, OSError):
            if time.time() > deadline:
                return f  # 拿不到锁也不阻塞任务，宁可并发也别漏检
            time.sleep(0.5)


if __name__ == "__main__":
    _lock = _acquire_run_lock()
    sys.exit(main())
