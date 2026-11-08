# -*- coding: utf-8 -*-
"""验证 PushPlus 通道：手动触发工作流时用"""
import json, requests
cfg = json.load(open("config.json", encoding="utf-8"))
p = {
    "token": cfg.get("pushplus_token", ""),
    "title": "GitHub监测已就位",
    "content": "<b>钟山烟语补货监控</b><br>这条来自 GitHub Actions。<br>收到即说明这条通道也通，有补货会通知你。",
    "template": "html",
    "channel": "wechat",
}
if cfg.get("pushplus_topic"):
    p["topic"] = cfg["pushplus_topic"]
r = requests.post("http://www.pushplus.plus/send", json=p, timeout=20)
print("[测试推送]", r.status_code, r.text[:200])
