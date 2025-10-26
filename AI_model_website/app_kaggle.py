# app.py
# -*- coding: utf-8 -*-
"""
Flask inference for ByteTransformer（二分類：benign vs malicious）
- 只做推論，不 import train_transformer.py
- 從 'byte_transformer.pt' 讀取：model、config、extra_cols、best_threshold、logT、malicious_id
- 對輸入 payload 自動解析（hex / token / 文字或 JSON），計算 extra_cols 與手工特徵，再推論
"""

import math, json, re, string
import numpy as np
import torch
import torch.nn as nn
from flask import Flask, request, render_template_string
import config

# -------------------------------
# 常數（需與訓練一致）
# -------------------------------
CLS_ID, PAD_ID, VOCAB_SIZE = 256, 257, 258
DEFAULT_MAX_LEN = 1024
HAND_DIM = 4 + 16  # len_norm, entropy/8, printable_ratio, unique_ratio + 16-bin

# -------------------------------
# 工具：payload 解析 & 特徵
# -------------------------------
def parse_payload(text, max_len=DEFAULT_MAX_LEN):
    """支援：純 hex、token(41 FF / 0x41)、十進位、或原始 JSON/文字（UTF-8 編碼）。"""
    if text is None:
        return []
    s = str(text).strip()
    if not s:
        return []
    compact = s.replace(' ', '').replace(',', '')
    # 1) 純十六進位字串
    if len(compact) >= 2 and len(compact) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in compact):
        try:
            arr = [int(compact[i:i+2], 16) for i in range(0, len(compact), 2)]
            return arr[: max_len - 1]
        except Exception:
            pass
    # 2) token 串
    toks = s.replace(',', ' ').split()
    out = []
    numeric_like = True
    for tok in toks:
        try:
            if tok.lower().startswith('0x'):
                v = int(tok, 16)
            elif re.fullmatch(r'[0-9a-fA-F]{1,2}', tok):
                v = int(tok, 16)
            else:
                v = int(float(tok))
            out.append(max(0, min(255, v)))
        except Exception:
            numeric_like = False
            break
    if numeric_like and out:
        return out[: max_len - 1]
    # 3) JSON 或原文 → UTF-8 bytes
    try:
        obj = json.loads(s)
        def _flatten(o):
            if isinstance(o, dict):
                parts = []
                for k in sorted(o.keys()):
                    parts.append(str(k))
                    parts.append(_flatten(o[k]))
                return ' '.join(parts)
            if isinstance(o, (list, tuple)):
                return ' '.join(_flatten(x) for x in o)
            return str(o)
        s_text = _flatten(obj)
    except Exception:
        s_text = s
    b = s_text.encode('utf-8', errors='ignore')
    return list(b[: max_len - 1])

def byte_features(b, max_len=DEFAULT_MAX_LEN):
    """與訓練一致的手工特徵。"""
    if not b:
        return [0.0, 0.0, 0.0, 0.0] + [0.0]*16
    n = len(b)
    cnt = [0]*256
    for x in b:
        cnt[x] += 1
    probs = [c/n for c in cnt if c > 0]
    ent = -sum(p*math.log2(p) for p in probs)  # 0~8
    printable = sum(1 for x in b if chr(x) in string.printable)/n
    uniq = sum(1 for c in cnt if c > 0) / 256.0
    bins = [0]*16
    for x in b:
        bins[x//16] += 1
    bins = [v/n for v in bins]
    return [n/float(max_len), ent/8.0, printable, uniq] + bins

def runtime_numeric_features(payload_text: str, b):
    """推論端重建訓練用 extra_cols（你資料表中的7欄）。"""
    # 用 bytes 還原可讀文字（若可）
    try:
        txt = bytes(b).decode('utf-8', errors='ignore')
    except Exception:
        txt = str(payload_text or "")

    # payload_len
    payload_len = float(len(b))
    # ascii_printable_ratio
    ascii_printable_ratio = (sum(ch in string.printable for ch in txt) / float(len(txt))) if len(txt) else 0.0
    # entropy（對 bytes）
    if b:
        n = len(b); cnt = [0]*256
        for x in b: cnt[x]+=1
        probs = [c/n for c in cnt if c>0]
        entropy = -sum(p*math.log2(p) for p in probs)
    else:
        entropy = 0.0
    # num_digits / num_symbols（對文字）
    num_digits = float(sum(c.isdigit() for c in txt))
    num_symbols = float(sum((c in string.punctuation) for c in txt))
    # risk_score_seed（關鍵字）
    low  = ["pwd","id","ls","whoami","get_config"]
    mid  = [";","&&","|","||","wget","curl","/etc/passwd","chmod","chown","telnet"]
    high = ["/bin/sh","bash","nc ","netcat","python -c","mkfifo","rm -rf",";sh",";bash"]
    t = txt.lower()
    risk = 0.0
    risk += 0.1*sum(k in t for k in low)
    risk += 0.3*sum(k in t for k in mid)
    risk += 0.6*sum(k in t for k in high)
    risk = min(risk, 1.0)
    # temperature（長度 proxy）
    temperature = 0.0
    if len(b) > 256: temperature = 0.2
    if len(b) > 512: temperature = 0.5
    if len(b) > 768: temperature = 0.8
    return {
        'payload_len': payload_len,
        'ascii_printable_ratio': ascii_printable_ratio,
        'entropy': entropy,
        'num_digits': num_digits,
        'num_symbols': num_symbols,
        'risk_score_seed': risk,
        'temperature': temperature,
    }

# -------------------------------
# 模型定義（與訓練一致）
# -------------------------------
class TempScaler(nn.Module):
    def __init__(self):
        super().__init__()
        self.logT = nn.Parameter(torch.zeros(1))
    def forward(self, logits):
        return logits / torch.exp(self.logT)

class SinusoidalPositionalEncoding(nn.Module):
    def __init__(self, d_model, max_len=4096):
        super().__init__()
        pe = torch.zeros(max_len, d_model)
        pos = torch.arange(0, max_len).unsqueeze(1).float()
        div = torch.exp(torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model))
        pe[:, 0::2] = torch.sin(pos*div)
        pe[:, 1::2] = torch.cos(pos*div)
        self.register_buffer('pe', pe)
    def forward(self, x):
        T = x.size(1)
        return x + self.pe[:T, :]

class ByteTransformer(nn.Module):
    def __init__(self, n_cls, extra_dim, d_model, nhead, layers, dropout):
        super().__init__()
        self.emb = nn.Embedding(VOCAB_SIZE, d_model)
        self.pos = SinusoidalPositionalEncoding(d_model)
        enc = nn.TransformerEncoderLayer(d_model, nhead, d_model*2, dropout=dropout, batch_first=True)
        self.enc = nn.TransformerEncoder(enc, layers, enable_nested_tensor=False)
        self.drop = nn.Dropout(dropout)
        self.fc_extra = nn.Linear(extra_dim, d_model)
        self.cls = nn.Linear(d_model*2, n_cls)
    def forward(self, ids, mask, extra):
        x = self.emb(ids)
        x = self.pos(x)
        pad_mask = (mask == 0).bool()
        x = self.enc(x, src_key_padding_mask=pad_mask)[:, 0]  # CLS pooling
        x = self.drop(x)
        e = torch.relu(self.fc_extra(extra)) if extra.size(1)>0 else torch.zeros(x.size(0), x.size(1), device=x.device)
        return self.cls(torch.cat([x, e], dim=-1))

# -------------------------------
# 載入 ckpt & 建模（修正鍵名 + hand_dim）
# -------------------------------
CKPT = torch.load('byte_transformer_kaggle.pt', map_location='cpu')

label2id       = CKPT['label2id']
id2label_raw   = CKPT['id2label']
id2label = {int(k): v for k, v in (id2label_raw.items() if isinstance(id2label_raw, dict) else enumerate(id2label_raw))}

extra_cols     = CKPT.get('extra_cols', [])
extra_mean     = CKPT.get('extra_mean', {})   # ← 修正鍵名
extra_std      = CKPT.get('extra_std', {})    # ← 修正鍵名
hand_dim_ckpt  = int(CKPT.get('hand_dim', HAND_DIM))  # ← 從 ckpt 取 hand_dim
cfg            = CKPT['config']
best_threshold = float(CKPT.get('best_threshold', 0.5)) if CKPT.get('best_threshold') is not None else 0.5
logT           = CKPT.get('logT', 0.0)
malicious_id   = int(CKPT.get('malicious_id', 1 if len(label2id)==2 else 0))
max_len        = int(cfg.get('max_len', DEFAULT_MAX_LEN))

# 防呆：logT 合法化
try:
    if not (isinstance(logT, (int, float)) and math.isfinite(logT)):
        logT = 0.0
except Exception:
    logT = 0.0

# extra 維度 = (數值特徵欄位數) + hand_dim（以 ckpt 為準）
extra_dim = (len(extra_cols) if extra_cols else 0) + hand_dim_ckpt

model = ByteTransformer(
    n_cls=len(label2id), extra_dim=extra_dim,
    d_model=cfg['d_model'], nhead=cfg['n_head'],
    layers=cfg['n_layer'], dropout=cfg['dropout']
)
state = CKPT.get('model') or CKPT.get('state_dict') or CKPT.get('model_state_dict')
model.load_state_dict(state, strict=True)
model.eval()

scaler = TempScaler()
with torch.no_grad():
    scaler.logT.copy_(torch.tensor([logT]))
scaler.eval()

# -------------------------------
# 推論
# -------------------------------
@torch.no_grad()
def infer_once(payload_text: str, decision_mode: str = "argmax", threshold: float | None = None):
    # 解析 bytes
    b = parse_payload(payload_text, max_len)

    # 手工特徵
    hand = np.array(byte_features(b, max_len), dtype=np.float32)

    # extra_cols（依欄位順序）+ 同訓練標準化
    feats = runtime_numeric_features(payload_text, b)
    vals = []
    for c in (extra_cols or []):
        v = float(feats.get(c, 0.0))
        if c in extra_mean and c in extra_std and extra_std[c]:
            v = (v - extra_mean[c]) / extra_std[c]
        vals.append(v)
    extra_numeric = np.array(vals, dtype=np.float32) if extra_cols else np.zeros((0,), dtype=np.float32)
    extra = np.concatenate([extra_numeric, hand], axis=0)

    # 組張量
    ids  = torch.tensor([[CLS_ID] + b], dtype=torch.long)
    mask = (ids != PAD_ID).long()
    extra_t = torch.tensor(extra, dtype=torch.float32).unsqueeze(0)

    # 前向 + 安全 softmax
    logits = model(ids, mask, extra_t)
    scaled = scaler(logits)
    probs_t = torch.softmax(scaled if torch.isfinite(scaled).all() else logits, dim=-1)[0]
    probs = torch.nan_to_num(probs_t, nan=0.5/len(id2label), posinf=1.0, neginf=0.0).cpu().numpy()

    # 惡意機率（顯示用）
    p_mal = float(probs[malicious_id]) if len(probs) == 2 else float(probs[int(np.argmax(probs))])

    # 決策：argmax 或 threshold
    if decision_mode == "th" and len(probs) == 2 and threshold is not None:
        is_mal = (p_mal >= float(threshold))
        pred_id = malicious_id if is_mal else (1 - malicious_id)
    else:
        pred_id = int(np.argmax(probs))
        is_mal = (pred_id == malicious_id)

    return {
        "bytes": b,
        "p_mal": p_mal,
        "pred_id": pred_id,
        "pred_label": id2label.get(pred_id, str(pred_id)),
        "probs": { id2label.get(i, str(i)): float(p) for i,p in enumerate(probs) },
        "hand": hand.tolist(),
        "is_mal": is_mal,
    }

# -------------------------------
# Flask
# -------------------------------
app = Flask(__name__)

HTML = """
<!doctype html>
<html><head><meta charset="utf-8"><title>Payload Detector (Transformer)</title>
<style>
 body{font-family:Arial, sans-serif;margin:40px}
 .card{max-width:960px;margin:0 auto;padding:24px;border-radius:16px;box-shadow:0 10px 30px rgba(0,0,0,.05)}
 textarea{width:100%;height:180px;font-family:monospace;font-size:14px;padding:10px;border-radius:8px;border:1px solid #ddd}
 button{padding:10px 16px;background:#111827;color:#fff;border-radius:8px;border:none;cursor:pointer}
 .pill{display:inline-block;padding:6px 10px;border-radius:999px;font-weight:bold}
 .mal{background:#fee2e2;color:#991b1b} .ben{background:#dcfce7;color:#166534}
 .meta{font-size:13px;color:#666;margin-top:8px;word-break:break-word}
 pre{background:#f7f7f7;padding:12px;border-radius:8px;overflow-x:auto}
</style></head><body>
<div class="card">
<h2>Payload Detector (Transformer)</h2>
<form method="POST" action="/" autocomplete="off">
  <p>請貼上 <b>payload</b>（支援：<code>AA FF 0d</code>、<code>0x41,0x42</code>、十六進位字串或 JSON）：</p>
  <textarea name="payload">{{ payload or "" }}</textarea>
  <p style="margin-top:8px"><button type="submit">預測</button></p>
</form>

{% if res %}
<hr/>
<p><span class="pill {{ 'mal' if is_mal else 'ben' }}">{{ '惡意 payload' if is_mal else '正常 payload' }}</span></p>
<div class="meta">p(malicious) = {{ p_mal }} ｜ 阈值 = {{ best_threshold }}</div>
<div class="meta">類別機率：{{ probs }}</div>
<h4>十六進位視圖</h4>
<pre>{{ hex_view }}</pre>
{% endif %}

<div class="meta" style="margin-top:20px">config={{ cfg }} ｜ extra_cols={{ extra_cols }} ｜ malicious_id={{ malicious_id }}</div>
</div></body></html>
"""

import paho.mqtt.client as mqtt
import threading, queue, uuid,json,time

MQTT_HOST, MQTT_PORT=config.MQTT_HOST, config.MQTT_PORT
TOPIC_FORWARD="pipeline/forward/{device_id}"
TOPIC_ACK="device/{device_id}/ack"
TOPIC_OUTPUT="device/{device_id}/output"
TOPIC_CRASH="device/{device_id}/crash"

mqttc=mqtt.Client(client_id="web-gateway")
event_q=queue.Queue(maxsize=1000)

def on_connect(client, userdata, flags, rc):
    print("MQTT connected:", rc)
    client.subscribe("device/+/ack",qos=1)
    client.subscribe("device/+/output",qos=1)
    client.subscribe("device/+/crash",qos=1)

def on_message(client, userdata,msg):
    try:
        payload=msg.payload.decode("utf-8",errors="ignore")
        data=json.loads(payload)
    except Exception:
        data={"raw": msg.payload.hex()}
    print(f"[MQTT] {msg.topic} -> {data}")
    event_q.put({"topic": msg.topic, "data": data, "ts": time.time()})

mqttc.on_connect=on_connect
mqttc.on_message=on_message
mqttc.connect(MQTT_HOST,MQTT_PORT,keepalive=60)
threading.Thread(target=mqttc.loop_forever,daemon=True).start()

from flask import jsonify, Response, request, render_template_string

@app.route("/api/infer", methods=["POST"])
def api_infer():
    body=request.get_json(silent=True) or {}
    payload=body.get("payload", "")
    mode=(body.get("mode") or "th").lower()
    th=body.get("threshold")
    eff_th=best_threshold if th is None else float(th)
    res = infer_once(payload if isinstance(payload,str) else json.dumps(payload),decision_mode=mode, threshold=eff_th)
    return jsonify({
        "is_malicious": bool(res["is_mal"]),
        "p_malicious": float(res["p_mal"]),
        "pred_label": res["pred_label"],
        "threshold": eff_th
    }), (406 if res["is_mal"] else 200)

def normalize_device_payload(raw):
    """
    把前端送來的一個欄位 raw（可能是字串/JSON）→ 統一轉成裝置 payload
    規則：
    - 若已是 dict 且含 cmd：直接用
    - 若是字串且長得像 JSON 並含 cmd：parse 後直接用
    - 若是字串且像 run_cmd 小語法（ADD/ECHO 開頭）：當成 run_cmd
    - 其餘字串：當成 echo 的 text
    """
    if isinstance(raw, dict) and "cmd" in raw:
        return raw
    if isinstance(raw, str):
        s = raw.strip()
        # 嘗試把字串當 JSON
        try:
            obj = json.loads(s)
            if isinstance(obj, dict) and "cmd" in obj:
                return obj
        except Exception:
            pass
        # 小語法判斷
        up = s.upper()
        if up.startswith("ADD ") or up.startswith("ECHO "):
            return {"cmd": "run_cmd", "command": s}
        # 預設走 echo
        return {"cmd": "echo", "text": s}
    # 其他型別 → 變字串 echo
    return {"cmd": "echo", "text": str(raw)}

# ==== 新增：主入口（AI → MQTT 下發） ====
@app.route("/api/send_to_device", methods=["POST"])
def api_send_to_device():
    body = request.get_json(silent=True) or {}

    device_id  = body.get("device_id") or "esp-lab-01"
    raw_payload = body.get("payload", "")
    timeout_ms = int(body.get("timeout_ms", 5000))
    timeout_ms = max(500, min(timeout_ms, 20000))  # 0.5s ~ 20s 之間

    # 0) 基本驗證
    if raw_payload is None or (isinstance(raw_payload, str) and not raw_payload.strip()):
        return jsonify({"accepted": False, "reason": "empty_payload"}), 400

    # 1) 規範化：把單一欄位轉成裝置要吃的 payload
    device_payload = normalize_device_payload(raw_payload)

    # 2) 先跑 AI 決策（用規範化前或後都可以；這裡用原始字串優先，否則用 JSON）
    raw_for_ai = raw_payload if isinstance(raw_payload, str) else json.dumps(raw_payload, ensure_ascii=False)
    res = infer_once(raw_for_ai, decision_mode="th", threshold=best_threshold)
    if res["is_mal"]:
        return jsonify({
            "accepted": False,
            "reason": "blocked_by_model",
            "p_malicious": float(res["p_mal"]),
            "threshold": float(best_threshold)
        }), 406

    # 3) 檢查 MQTT 是否可用
    if not mqttc or not mqttc.is_connected():
        return jsonify({"accepted": False, "reason": "mqtt_unavailable"}), 503

    # 4) 組 forward 並發佈
    req_id = str(uuid.uuid4())
    msg = {"req_id": req_id, "payload": device_payload, "exec_hint": {"timeout_ms": timeout_ms}}

    try:
        info = mqttc.publish(TOPIC_FORWARD.format(device_id=device_id), json.dumps(msg), qos=1)
        # paho 1.x：wait_for_publish 才能確保送出去（非必要）
        info.wait_for_publish(timeout=2.0)
    except Exception as e:
        return jsonify({"accepted": False, "reason": "mqtt_publish_error", "error": str(e)}), 502

    return jsonify({
        "accepted": True,
        "req_id": req_id,
        "device_id": device_id,
        "forward": msg,                      # 方便你們在前端/除錯看到實際送出的內容
        "p_malicious": float(res["p_mal"]),
        "threshold": float(best_threshold)
    }), 202

# ==== 新增：SSE 事件流，把裝置回報推到前端 ====
@app.route("/events")
def sse_events():
    def gen():
        while True:
            ev=event_q.get()
            yield "data: "+json.dumps(ev,ensure_ascii=False)+ "\n\n"
    return Response(gen(), mimetype="text/event-stream") 


# ---- 簡易 MQTT 回報頁（即時看 ack / output / crash）----
REPORT_HTML = """
<!doctype html><meta charset="utf-8"><title>MQTT Reports</title>
<style>
 body{font-family:sans-serif;max-width:1000px;margin:24px auto}
 #log{background:#0b1220;color:#b6ffb6;border-radius:8px;padding:12px;height:420px;overflow:auto;white-space:pre-wrap}
 .tag{display:inline-block;padding:2px 8px;border-radius:999px;margin-right:6px;font-size:12px}
 .ACK{background:#e0f2fe;color:#075985}.OUTPUT{background:#dcfce7;color:#166534}.CRASH{background:#fee2e2;color:#991b1b}
 .ctl{margin:8px 0}
</style>
<h2>MQTT 回報（即時）</h2>
<div class="ctl">
  <label><input type="checkbox" id="showAck" checked> 顯示 ACK</label>
  <label><input type="checkbox" id="showOut" checked> 顯示 OUTPUT</label>
  <label><input type="checkbox" id="showCrash" checked> 顯示 CRASH</label>
  <input id="kw" placeholder="關鍵字過濾 (req_id / topic / 內容)" style="width:280px">
  <button onclick="clearLog()">清空</button>
</div>
<pre id="log"></pre>

<script>
const logEl = document.getElementById('log');
const showAck = document.getElementById('showAck');
const showOut = document.getElementById('showOut');
const showCrash = document.getElementById('showCrash');
const kw = document.getElementById('kw');

function colorOf(topic){
  if(topic.includes('/ack')) return 'ACK';
  if(topic.includes('/output')) return 'OUTPUT';
  if(topic.includes('/crash')) return 'CRASH';
  return '';
}

function pushLine(obj){
  const t = new Date(obj.ts*1000).toLocaleTimeString();
  const tag = colorOf(obj.topic);
  const line = `[${t}] [${obj.topic}] ${JSON.stringify(obj.data)}`;
  const passKW = !kw.value || line.toLowerCase().includes(kw.value.toLowerCase());
  const passType = (tag==='ACK' && showAck.checked) || (tag==='OUTPUT' && showOut.checked) || (tag==='CRASH' && showCrash.checked);
  if(passKW && passType){
    logEl.textContent += line + "\\n";
    logEl.scrollTop = logEl.scrollHeight;
  }
}

function clearLog(){ logEl.textContent=''; }

const es = new EventSource('/events');
es.onmessage = (e)=>{ try{ pushLine(JSON.parse(e.data)); }catch(_){ } };
</script>
"""

@app.route("/mqtt")
def mqtt_report():
    from flask import render_template_string
    return render_template_string(REPORT_HTML)


@app.route("/", methods=["GET","POST"])
def home():
    txt = request.form.get("payload") if request.method=="POST" else ""

    # ?mode=argmax 或 ?mode=th
    mode = request.args.get("mode", "argmax").lower()
    # ?th=0.075 ；若沒帶就用 ckpt 的 best_threshold
    th_q = request.args.get("th")
    eff_th = best_threshold if th_q is None else float(th_q)

    res = infer_once(txt, decision_mode=mode, threshold=eff_th) if txt.strip() else None
    return render_template_string(
        HTML,
        payload=txt,
        res=res,
        is_mal=(res and res["is_mal"]),
        p_mal=(round(res["p_mal"],6) if res else None),
        hex_view=(' '.join(f'{x:02x}' for x in (res["bytes"] if res else []))),
        probs=(json.dumps(res["probs"], ensure_ascii=False) if res else ""),
        best_threshold=eff_th,   # 顯示目前生效門檻
        cfg=cfg,
        extra_cols=extra_cols,
        malicious_id=malicious_id
    )


@app.route("/debug")
def debug():
    return {
        "label2id": label2id,
        "id2label": id2label,
        "malicious_id": malicious_id,
        "best_threshold": best_threshold,
        "extra_cols": extra_cols,
        "extra_cols_mean": extra_mean,
        "extra_cols_std": extra_std,
        "config": cfg,
        "logT": float(logT),
    }

if __name__ == "__main__":
    app.run(host=config.server_host, port=config.server_port, debug=False)
