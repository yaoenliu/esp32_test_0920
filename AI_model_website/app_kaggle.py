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
 textarea{width:100%;height:220px;font-family:monospace;font-size:14px;padding:10px;border-radius:8px;border:1px solid #ddd}
 button{padding:10px 16px;background:#111827;color:#fff;border-radius:8px;border:none;cursor:pointer}
 input[type=text]{padding:8px;border:1px solid #ddd;border-radius:8px}
 .pill{display:inline-block;padding:6px 10px;border-radius:999px;font-weight:bold}
 .mal{background:#fee2e2;color:#991b1b} .ben{background:#dcfce7;color:#166534}
 .meta{font-size:13px;color:#666;margin-top:8px;word-break:break-word}
 pre{background:#f7f7f7;padding:12px;border-radius:8px;overflow-x:auto}
 .row{display:flex;gap:12px;align-items:center;margin:10px 0}
 #resp{white-space:pre-wrap;background:#f7f7f7;padding:10px;border-radius:8px;margin-top:8px}
</style></head><body>
<div class="card">
  <h2>Payload Detector (Transformer)</h2>

  <div class="row">
    <label>Device ID：
      <input id="device_id" type="text" value="esp-lab-01" placeholder="裝置 ID（MQTT topic 用）">
    </label>
    <label>
      <input id="autoSend" type="checkbox" checked>
      AI 通過就送到裝置
    </label>
    <a href="/mqtt" target="_blank">開啟 MQTT 回報頁</a>
  </div>

  <form id="f" autocomplete="off" onsubmit="return doPredict(event)">
    <p>請貼上 <b>payload</b>（支援：<code>AA FF 0d</code>、<code>0x41,0x42</code>、十六進位字串或 JSON）：</p>
    <textarea id="payload" name="payload"></textarea>
    <p style="margin-top:8px">
      <button type="submit">預測（通過時可自動送裝置）</button>
      <button type="button" onclick="sendDirect()">直接送到裝置</button>
    </p>
  </form>

  <div id="view"></div>
  <div id="resp"></div>

  <div class="meta" style="margin-top:20px">
    config={{ cfg }} ｜ extra_cols={{ extra_cols }} ｜ malicious_id={{ malicious_id }}
  </div>
</div>

<script>
async function doPredict(e){
  e.preventDefault();
  const payload = document.getElementById('payload').value;
  if(!payload.trim()){ alert('請輸入 payload'); return false; }
  const view = document.getElementById('view');
  const respBox = document.getElementById('resp');
  view.innerHTML = '預測中…'; respBox.textContent = '';

  // 1) 先對 /api/infer 做推論
  const r = await fetch('/api/infer', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({payload: payload, mode: 'th'})
  });
  const ok = r.status === 200;
  const data = await r.json().catch(()=> ({}));

  // 顯示 AI 結果
  if(ok){
    view.innerHTML = `<p><span class="pill ben">正常 payload</span></p>
      <div class="meta">p(malicious) = ${data.p_malicious} ｜ 阈值 = ${data.threshold}</div>`;
    // 2) 若勾選自動送，就呼叫 /api/send_to_device
    if(document.getElementById('autoSend').checked){
      await sendToDevice(payload);
    }
  }else{
    view.innerHTML = `<p><span class="pill mal">惡意 payload</span></p>
      <div class="meta">p(malicious) = ${data.p_malicious ?? 'N/A'} ｜ 阈值 = ${data.threshold ?? 'N/A'}</div>`;
  }
  return false;
}

async function sendToDevice(payload){
  const deviceId = document.getElementById('device_id').value || 'esp-lab-01';
  const respBox = document.getElementById('resp');
  respBox.textContent = '送裝置中…';
  const r = await fetch('/api/send_to_device', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ device_id: deviceId, payload })
  });
  const txt = await r.text();
  respBox.textContent = `HTTP ${r.status}\n` + txt;
}

async function sendDirect(){
  const payload = document.getElementById('payload').value;
  if(!payload.trim()){ alert('請輸入 payload'); return; }
  await sendToDevice(payload);
}
</script>
</body></html>
"""

import paho.mqtt.client as mqtt
import threading, queue, uuid,json,time

MQTT_HOST, MQTT_PORT= config.MQTT_HOST, config.MQTT_PORT
TOPIC_FORWARD="pipeline/forward/{device_id}"
TOPIC_ACK="device/{device_id}/ack"
TOPIC_OUTPUT="device/{device_id}/output"
TOPIC_CRASH="device/{device_id}/crash"

mqttc=mqtt.Client(client_id="web-gateway")
event_q=queue.Queue(maxsize=1000)
def on_connect(client, userdata, flags, rc):
    print("MQTT connected:", rc)
    client.subscribe("device/+/crash",qos=1)
    client.subscribe("device/+/output",qos=1)
    client.subscribe("device/+/ack",qos=1)

def on_message(client, userdata, msg):
    # --- 1) 判斷 topic 類型 ---
    if msg.topic.endswith("/ack"):
        devst = "ack"
    elif msg.topic.endswith("/output"):
        devst = "output"
    elif msg.topic.endswith("/crash"):
        devst = "crash"
    else:
        devst = "unknown"

    # --- 2) 嘗試解析裝置原始 payload ---
    raw = msg.payload.decode("utf-8", errors="ignore").strip()
    norm = None
    try:
        obj = json.loads(raw)
        # 若已是你要的結構，直接用
        if isinstance(obj, dict) and ("status" in obj or "stdout" in obj or "msg" in obj):
            norm = obj
    except Exception:
        pass

    # --- 3) 正規化（不是 JSON 或結構不符 → 轉成你要的格式）---
    if norm is None:
        if devst in ("ack", "output"):
            # 視為成功輸出；純文字一律放 stdout
            norm = {"status": "ok", "stdout": raw or "ok"}
        elif devst == "crash":
            norm = {"status": "crash", "msg": raw or "crash"}
        else:
            norm = {"status": "ok", "stdout": raw}

    # --- 4) 弱標註 ---
    weak = None
    if devst == "crash":
        weak = "malicious"
    elif devst in ("ack", "output"):
        weak = "benign"

    # 由於不再使用 req_id，這裡不要從 data 取 req_id
    # device_id = "device/{id}/..." 的第二段
    parts = msg.topic.split("/")
    device_id = parts[1] if len(parts) > 1 else None

    # --- 5) 紀錄到 DB（device_msg 存正規化後的 JSON 字串）---
    

    # --- 6) 推到前端事件流（/mqtt 頁會看到）---
    event_q.put({"topic": msg.topic, "data": norm, "ts": time.time()})

mqttc.on_connect=on_connect
mqttc.on_message=on_message
mqttc.connect(MQTT_HOST,MQTT_PORT,keepalive=60)
threading.Thread(target=mqttc.loop_forever,daemon=True).start()

from flask import jsonify, Response, request, render_template_string

#SHELL_CHARS = r'[|&;`$><]' # 這是明顯shell injection字元，我對AI座前處理，你之後要測WFUZZ再把她清空測
#AI模型對於沒看過的字串依舊會顯示benign，我已經寫在報告裡了，
SHELL_CHARS=""
def normalize_spaces(payload: str) -> str:
    """
    統一格式：
      run_cmd ,   ADD   7  8   → run_cmd,ADD 7 8
      run_cmd , sub  3 -5      → run_cmd,SUB 3 -5
      run_cmd , echo  hi       → run_cmd,echo hi
      echo,   hello            → echo,hello
      start_temp_report , 10   → start_temp_report,10
    """
    if not isinstance(payload, str):
        return payload

    s = str(payload)

    # 1) 各種奇怪空白 → space
    s = re.sub(r'[\u00A0\u2000-\u200B\u3000]', ' ', s)
    s = s.replace("，", ",")
    s = s.replace("\t", " ")
    s = s.replace("\r", " ").replace("\n", " ")
    s = re.sub(r'\s+', ' ', s)
    s = re.sub(r'\s*,\s*', ', ', s)
    s = s.strip()

    # 2) run_cmd, ADD / SUB / echo
    m = re.match(r'^(run_cmd)\s*,\s*(ADD|SUB|echo)\s*(.*)$', s, flags=re.I)
    if m:
        cmd, sub, rest = m.groups()
        cmd = cmd.lower()     # run_cmd
        sub = sub.upper() if sub.lower() in ("add", "sub") else "echo"
        rest = rest.strip()
        if rest:
            return f"{cmd},{sub} {rest}"
        else:
            return f"{cmd},{sub}"

    # 3) echo, ...
    m = re.match(r'^(echo)\s*,\s*(.*)$', s, flags=re.I)
    if m:
        cmd, rest = m.groups()
        cmd = cmd.lower()
        rest = rest.strip()
        return f"{cmd},{rest}"

    # 4) start_temp_report, ...
    m = re.match(r'^(start_temp_report)\s*,\s*(.*)$', s, flags=re.I)
    if m:
        cmd, rest = m.groups()
        cmd = cmd.lower()
        rest = rest.strip()
        return f"{cmd},{rest}"

    return s



def has_shell_chars(text: str) -> bool:
    """檢查有沒有明顯 shell / XSS 符號"""
    if any(ch in text for ch in SHELL_CHARS):
        return True
    tl = text.lower()
    if "<script" in tl or "onerror=" in tl:
        return True
    return False

def rule_check(payload: str):
    s = payload.strip()

    # run_cmd,ADD / SUB / echo → 格式合法
    if re.match(r'^run_cmd,(ADD|SUB|echo)\b', s, flags=re.I):
        return "benign"

    # echo,<text>
    if re.match(r'^echo,', s, flags=re.I):
        return "benign"

    # start_temp_report,<num>
    """ ### 原本的嚴格規則（改成全給 AI 判斷）<=2自動判斷malicious
    m = re.match(r'^start_temp_report,(\S+)$', s, flags=re.I)
    if m:
        num_str = m.group(1)

        # 不是整數 → 給 AI 判斷
        if not num_str.lstrip("-").isdigit():
            return "benign"

        # 是整數 → 檢查大小
        n = int(num_str)
        if n <= 2:
            return "malicious"  # ★ 前處理直接擋
        return "benign"  # 把 >=3 給 AI
    """
    m = re.match(r'^start_temp_report,(\S+)$', s, flags=re.I)
    if m:
        return "benign"
    # 其他全部視為格式錯 → 惡意
    return "malicious"



@app.route("/api/infer", methods=["POST"])
def api_infer():
    body = request.get_json(silent=True) or {}
    payload = body.get("payload", "")
    mode = (body.get("mode") or "th").lower()
    th = body.get("threshold")
    eff_th = best_threshold if th is None else float(th)

    # 原始字串 & 正規化空白
    payload_str_raw = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False)
    payload_str = normalize_spaces(payload_str_raw)

    print("[DEBUG raw       ]", repr(payload_str_raw))
    print("[DEBUG normalized]", repr(payload_str))

    # 1) 先用 rule_check 看「格式」對不對
    rule_label = rule_check(payload_str)

    if rule_label == "malicious":
        print("[rule-block] format error:", repr(payload_str))
        return jsonify({
            "is_malicious": True,
            "pred_label": "malicious_format",
            "p_malicious": 1.0,
            "threshold": eff_th,
            "reason": "format_error",
            "source": "rule",
            "normalized_payload": payload_str,
        }), 406

    # 1.5) ★ 針對 echo 類型，加上「沒有 shell 字元就直接當 benign」的白名單 ★
    s_lower = payload_str.lower()

    # (a) run_cmd,echo ...
    m = re.match(r'^run_cmd,echo\s+(.*)$', payload_str, flags=re.I)
    if m:
        echo_text = m.group(1).strip()
        if has_shell_chars(echo_text):
            # 有 shell 符號 → 直接惡意，不給 AI 決定
            print("[rule-block] echo shell inj:", repr(payload_str))
            return jsonify({
                "is_malicious": True,
                "pred_label": "malicious_echo",
                "p_malicious": 1.0,
                "threshold": eff_th,
                "reason": "echo_shell_chars",
                "source": "rule",
                "normalized_payload": payload_str,
            }), 406
        else:
            # 純 echo 文本 → 直接當 benign，AI 只算參考分數
            res_ai = infer_once(payload_str, decision_mode=mode, threshold=eff_th)
            return jsonify({
                "is_malicious": bool(res_ai["is_mal"]),                 
                "p_malicious": float(res_ai["p_mal"]),     # 只是顯示用
                "pred_label": "benign_echo_rule",
                "threshold": eff_th,
                "reason": "echo_no_shell_chars",
                "source": "rule+ai",
                "normalized_payload": payload_str,
            }), 200

    # (b) echo, ...
    m = re.match(r'^echo,(.*)$', payload_str, flags=re.I)
    if m:
        echo_text = m.group(1).strip()
        if has_shell_chars(echo_text):
            print("[rule-block] echo shell inj:", repr(payload_str))
            return jsonify({
                "is_malicious": True,
                "pred_label": "malicious_echo",
                "p_malicious": 1.0,
                "threshold": eff_th,
                "reason": "echo_shell_chars",
                "source": "rule",
                "normalized_payload": payload_str,
            }), 406
        else:
            res_ai = infer_once(payload_str, decision_mode=mode, threshold=eff_th)
            return jsonify({
                "is_malicious": bool(res_ai["is_mal"]),
                "p_malicious": float(res_ai["p_mal"]),
                "pred_label": "benign_echo_rule",
                "threshold": eff_th,
                "reason": "echo_no_shell_chars",
                "source": "rule+ai",
                "normalized_payload": payload_str,
            }), 200

    # 2) 其它類型（ADD / SUB / start_temp_report ...）就交給 AI 決定
    res_ai = infer_once(
        payload_str,
        decision_mode=mode,
        threshold=eff_th
    )

    return jsonify({
        "is_malicious": bool(res_ai["is_mal"]),
        "p_malicious": float(res_ai["p_mal"]),
        "pred_label": res_ai["pred_label"],
        "threshold": eff_th,
        "source": "ai",
        "normalized_payload": payload_str,
    }), (406 if res_ai["is_mal"] else 200)



def _debug_req(prefix=""):
    try:
        print(f"[{prefix}] CT={request.headers.get('Content-Type')!r} "
              f"len={request.content_length} "
              f"raw[:200]={request.get_data(cache=False)[:200]!r}")
    except Exception as e:
        print(f"[{prefix}] debug_err={e}")

def _robust_json():
    """
    更耐髒的 JSON 解析：
      1) Content-Type 是 json → 用 get_json()
      2) 不行 → 直接用 raw bytes 手動 json.loads
      3) 再不行 → 試試表單(request.form)
    回傳 dict (失敗回 {} )
    """
    ct = (request.headers.get("Content-Type") or "").lower()
    body = {}
    if "application/json" in ct:
        body = request.get_json(silent=True) or {}
    if not body:
        raw = request.get_data(cache=False)
        if raw:
            try:
                body = json.loads(raw.decode("utf-8", errors="ignore")) or {}
            except Exception:
                body = {}
    if not body and request.form:
        body = request.form.to_dict()
    return body

def to_device_json(payload_text: str):
    """
    將輸入框的一行字串轉成 target device 期望的 JSON。
    - 支援：'run_cmd, ADD 1 2' → {"cmd":"run_cmd","command":"ADD 1 2"}
    - 若本來就是 JSON，且已含 cmd/command，則直接回傳該物件
    - 其他指令可在這裡擴充（echo、db_query…）
    """
    s = (payload_text or "").strip()
    if not s:
        return None  # 空 payload

    # 1) 若本來就是 JSON（例如 {"cmd":"run_cmd","command":"ADD 1 2"}）
    try:
        obj = json.loads(s)
        if isinstance(obj, dict) and ("cmd" in obj):
            return obj  # 已是裝置格式
    except Exception:
        pass  # 不是 JSON，就走字串解析

    # 2) 解析「<keyword> , <rest>」型式
    m = re.match(r'^\s*([A-Za-z_]+)\s*,\s*(.+?)\s*$', s)
    if not m:
        # 格式不符，你也可以選擇丟回 None 讓前端顯示錯誤
        return {"cmd": "raw", "raw": s}

    keyword = m.group(1).lower()
    rest    = m.group(2)

    # 只針對你目前需求：run_cmd → {"cmd":"run_cmd","command":"..."}
    if keyword == "run_cmd":
        return {"cmd": "run_cmd", "command": rest}

    # 你之後若要支援：
    # echo, hello world  → {"cmd":"echo","text":"hello world"}
    # db_query, GET user → {"cmd":"db_query","query":"GET user"}
    # 可以在這裡擴充：
    if keyword == "echo":
        return {"cmd": "echo", "text": rest}
    if keyword == "db_query":
        return {"cmd": "db_query", "query": rest}
    if keyword == "start_temp_report":
        return {"cmd": "start_temp_report", "interval": rest}

    # 不認得的指令：保底
    return {"cmd": keyword, "args": rest}

@app.route("/api/send_to_device", methods=["POST"])
def api_send_to_device():
    body = request.get_json(silent=True) or {}
    device_id = body.get("device_id") or "esp-lab-01"
    payload   = body.get("payload")

    if not payload or not isinstance(payload, str):
        return jsonify({"accepted": False, "reason": "empty_payload"}), 400

    # ★ 不再重新跑 AI（infer）, 直接轉裝置格式後送出
    dev_msg = to_device_json(payload)
    if not dev_msg:
        return jsonify({"accepted": False, "reason": "invalid_payload"}), 400

    req_id = str(uuid.uuid4())

    mqttc.publish(
        TOPIC_FORWARD.format(device_id=device_id),
        json.dumps(dev_msg, ensure_ascii=False),
        qos=1
    )

    # 回傳 202 表示成功送出
    return jsonify({
        "accepted": True,
        "req_id": req_id,
        "normalized_payload": payload,
        "source": "send_only"
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
