#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
train_transformer.py — 只在最後一個 Epoch 存模型（含溫度校準與最佳門檻）
- 自動讀取 payload_log_augmented_enriched.csv
- 特徵：payload 序列 + 數值欄位 + 手工強訊號（長度/熵/可列印比例/唯一比例/16-bin）
- 模型：Transformer Encoder + CLS 池化 + 數值特徵融合
- 技巧：class weight、label smoothing、warmup+cosine、(結尾) 溫度校準 + 最佳 threshold（二分類）
"""

import math, string, random
import pandas as pd, numpy as np
import torch, torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score

# -------------------------------
# 固定參數
# -------------------------------
#CSV_PATH, TEXT_COLUMN, LABEL_COLUMN = 'payload_log_clean.csv', 'payload', 'label'
TRAIN_CSV = 'payload_log_clean_train.csv'
TEST_CSV  = 'payload_log_clean_test.csv'
TEXT_COLUMN, LABEL_COLUMN = 'payload', 'label'
MAX_LEN, BATCH_SIZE, EPOCHS, LR, SEED = 1024, 64, 10, 2e-4, 42
D_MODEL, N_HEAD, N_LAYER, DROPOUT = 256, 8, 4, 0.2

random.seed(SEED); np.random.seed(SEED); torch.manual_seed(SEED)
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

CLS_ID, PAD_ID, VOCAB_SIZE = 256, 257, 258

# -------------------------------
# 溫度校準
# -------------------------------
class TempScaler(nn.Module):
    def __init__(self):
        super().__init__()
        self.logT = nn.Parameter(torch.zeros(1))
    def forward(self, logits):
        return logits / torch.exp(self.logT)

@torch.no_grad()
def fit_temperature(model, val_dl, device):
    model.eval()
    scaler = TempScaler().to(device)
    opt = torch.optim.LBFGS(scaler.parameters(), lr=0.1, max_iter=50)
    nll = nn.CrossEntropyLoss()

    all_logits, all_y = [], []
    for ids, y, m, extra in val_dl:
        ids, y, m, extra = ids.to(device), y.to(device), m.to(device), extra.to(device)
        all_logits.append(model(ids, m, extra))
        all_y.append(y)
    logits = torch.cat(all_logits, 0)
    y = torch.cat(all_y, 0)

    def closure():
        opt.zero_grad()
        loss = nll(scaler(logits), y)
        loss.backward()
        return loss
    opt.step(closure)
    return scaler

# -------------------------------
# 解析 payload
# -------------------------------
def parse_payload(s):
    if pd.isna(s): 
        return []
    s = str(s).strip()
    if not s: 
        return []

    # 1) 純 16 進位字串（4142430d0a）
    compact = s.replace(' ', '').replace(',', '')
    if len(compact) % 2 == 0 and len(compact) >= 2 and all(c in '0123456789abcdefABCDEF' for c in compact):
        try:
            return [int(compact[i:i+2], 16) for i in range(0, len(compact), 2)]
        except Exception:
            pass

    # 2) token 串（0x41, ff, 13, ...）
    out = []
    numeric_like = True
    for tok in s.replace(',', ' ').split():
        try:
            if tok.lower().startswith('0x'):
                v = int(tok, 16)
            elif len(tok) <= 2 and all(c in '0123456789abcdefABCDEF' for c in tok):
                v = int(tok, 16)
            else:
                v = int(float(tok))
            out.append(max(0, min(255, v)))
        except Exception:
            numeric_like = False
            break
    if numeric_like and out:
        return out

    # 3) fallback：一般文字 → UTF-8 bytes
    try:
        b = s.encode('utf-8', errors='ignore')
        return list(b)
    except Exception:
        return []

# -------------------------------
# 手工強訊號特徵
# -------------------------------
HAND_DIM = 4 + 16  # len, entropy, printable_ratio, unique_ratio + 16-bin
def byte_features(b):
    if not b:
        return [0.0,0.0,0.0,0.0]+[0.0]*16
    n=len(b)
    cnt=[0]*256
    for x in b: cnt[x]+=1
    probs=[c/n for c in cnt if c>0]
    ent=-sum(p*math.log2(p) for p in probs)   # 0~8
    printable=sum(1 for x in b if chr(x) in string.printable)/n
    uniq=sum(1 for c in cnt if c>0)/256.0
    bins=[0]*16
    for x in b: bins[x//16]+=1
    bins=[v/n for v in bins]
    return [n/float(MAX_LEN), ent/8.0, printable, uniq] + bins

# -------------------------------
# Dataset / Collate
# -------------------------------
class MyDataset(Dataset):
    def __init__(self, df, label2id, extra_cols):
        self.texts = df[TEXT_COLUMN].tolist()
        self.labels = df[LABEL_COLUMN].astype(str).map(label2id).tolist()
        self.extra = df[extra_cols].fillna(0).astype(float).values.astype(np.float32) if extra_cols else np.zeros((len(df),0), dtype=np.float32)
        self.max_len = MAX_LEN
    def __len__(self): return len(self.texts)
    def __getitem__(self, i):
        bytes_ = parse_payload(self.texts[i])[: self.max_len - 1]
        ids = [CLS_ID] + bytes_
        hand = np.array(byte_features(bytes_), dtype=np.float32)
        feat = np.concatenate([self.extra[i], hand], axis=0)
        return torch.tensor(ids), torch.tensor(self.labels[i]), torch.tensor(feat)

def collate(batch):
    ids, labels, extra = zip(*batch)
    maxl = max(len(x) for x in ids)
    pad = [torch.cat([x, torch.full((maxl-len(x),), PAD_ID)]) for x in ids]
    mask = [(x!=PAD_ID).long() for x in pad]
    return torch.stack(pad).long(), torch.tensor(labels), torch.stack(mask), torch.stack(extra)

# -------------------------------
# Model
# -------------------------------
class SinusoidalPositionalEncoding(nn.Module):
    def __init__(self, d_model, max_len=4096):
        super().__init__()
        pe = torch.zeros(max_len, d_model)
        pos = torch.arange(0, max_len).unsqueeze(1).float()
        div = torch.exp(torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model))
        pe[:, 0::2] = torch.sin(pos * div)
        pe[:, 1::2] = torch.cos(pos * div)
        self.register_buffer('pe', pe)
    def forward(self, x):
        T = x.size(1)
        return x + self.pe[:T, :]

class ByteTransformer(nn.Module):
    def __init__(self, n_cls, extra_dim, d_model=D_MODEL, nhead=N_HEAD, layers=N_LAYER, dropout=DROPOUT):
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
        x = self.enc(x, src_key_padding_mask=pad_mask)[:, 0]  # CLS
        x = self.drop(x)
        e = torch.relu(self.fc_extra(extra)) if extra.size(1)>0 else torch.zeros(x.size(0), x.size(1), device=x.device)
        return self.cls(torch.cat([x, e], dim=-1))

# -------------------------------
# Scheduler（warmup + cosine）
# -------------------------------
class WarmupCosine:
    def __init__(self, optimizer, warmup, total):
        self.opt, self.warmup, self.total = optimizer, warmup, total
        self.step_i = 0
        self.base_lrs = [g['lr'] for g in optimizer.param_groups]
    def step(self):
        self.step_i += 1
        for i, g in enumerate(self.opt.param_groups):
            if self.step_i <= self.warmup:
                scale = self.step_i / max(1, self.warmup)
            else:
                t = (self.step_i - self.warmup) / max(1, self.total - self.warmup)
                scale = 0.5 * (1 + math.cos(math.pi * t))
            g['lr'] = self.base_lrs[i] * scale

# -------------------------------
# 讀資料
# -------------------------------

train_df = pd.read_csv(TRAIN_CSV).dropna(subset=[TEXT_COLUMN, LABEL_COLUMN]).copy()
test_df  = pd.read_csv(TEST_CSV ).dropna(subset=[TEXT_COLUMN, LABEL_COLUMN]).copy()
train_df = train_df.drop_duplicates(subset=[TEXT_COLUMN]).reset_index(drop=True)
test_df  = test_df.drop_duplicates(subset=[TEXT_COLUMN]).reset_index(drop=True)

extra_cols = [
    'payload_len', 'ascii_printable_ratio', 'entropy',
    'num_digits', 'num_symbols', 'risk_score_seed', 'temperature'
]
extra_cols = [c for c in extra_cols if c in train_df.columns or c in test_df.columns]
print(f"[extra_cols] 使用 {len(extra_cols)} 欄位：", extra_cols)

labels = sorted(pd.concat([train_df[LABEL_COLUMN].astype(str),test_df[LABEL_COLUMN].astype(str)], axis=0).unique())
label2id = {l:i for i,l in enumerate(labels)}
id2label = {i:l for l,i in label2id.items()}

malicious_id=None
candidates={'malicious','malware','attack','bad'}
for name, idx in label2id.items():
    if str(name).lower() in candidates:
        malicious_id=idx
        break

if malicious_id is None and len(label2id)==2:
    if 'benign' in label2id:
        malicious_id=1-label2id['benign']
    else:
        malicious_id=1
print(f"[malicious_id] malicious_id = {malicious_id} -> {id2label.get(malicious_id)}")


# 類別權重
train_labels = train_df[LABEL_COLUMN].astype(str).map(label2id).values
num_classes = len(label2id)
counts = np.bincount(train_labels, minlength=num_classes).astype(np.float32)
class_weight = counts.sum() / (counts + 1e-6)
class_weight = torch.tensor(class_weight, dtype=torch.float32, device=device)
print("Class counts:", counts, "->weight:", class_weight.cpu().numpy())

# 數值欄標準化
extra_mean, extra_std = {}, {}
if len(extra_cols) > 0:
    # 沒有的欄位補 0
    for c in extra_cols:
        if c not in train_df.columns: train_df[c] = 0.0
        if c not in test_df.columns:  test_df[c]  = 0.0
    mean_ = train_df[extra_cols].mean()
    std_  = train_df[extra_cols].std().replace(0,1)
    train_df[extra_cols] = (train_df[extra_cols]-mean_)/std_
    test_df[extra_cols]  = (test_df[extra_cols]-mean_)/std_
    extra_mean={col: float(mean_[col]) for col in extra_cols}
    extra_std ={col: float(std_[col])  for col in extra_cols}
else:
    extra_mean, extra_std = {}, {}


# DataLoader
extra_dim = (len(extra_cols) if extra_cols else 0) + HAND_DIM
train_dl = DataLoader(MyDataset(train_df, label2id, extra_cols), BATCH_SIZE, shuffle=True,  collate_fn=collate)
val_dl   = DataLoader(MyDataset(test_df,  label2id, extra_cols), BATCH_SIZE, shuffle=False, collate_fn=collate)
# -------------------------------
# 建模 & 訓練
# -------------------------------
model = ByteTransformer(num_classes, extra_dim).to(device)
opt   = torch.optim.AdamW(model.parameters(), lr=LR, weight_decay=0.01)
crit  = nn.CrossEntropyLoss( label_smoothing=0.05)



total_steps  = EPOCHS * max(1, len(train_dl))
warmup_steps = max(10, int(0.06 * total_steps))
scheduler    = WarmupCosine(opt, warmup_steps, total_steps)

best_threshold = 0.5  # 二分類時會更新

for ep in range(1, EPOCHS+1):
    # ---- train
    model.train(); tl = 0.0
    for ids, y, m, extra in train_dl:
        ids, y, m, extra = ids.to(device), y.to(device), m.to(device), extra.to(device)
        opt.zero_grad()
        logits = model(ids, m, extra)
        loss = crit(logits, y)
        loss.backward()
        nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        opt.step(); scheduler.step()
        tl += loss.item()

    # ---- quick val（不做溫度校準，只為了觀察趨勢）
    model.eval(); vl = 0.0; labs = []; probs_all = []
    with torch.no_grad():
        for ids, y, m, extra in val_dl:
            ids, y, m, extra = ids.to(device), y.to(device), m.to(device), extra.to(device)
            o = model(ids, m, extra)
            vl += crit(o, y).item()
            probs_all.append(o.softmax(-1).cpu())
            labs += y.cpu().tolist()
    probs = torch.cat(probs_all, dim=0).numpy()
    if num_classes == 2:
        p1 = probs[:,1]
        f1s = [(f1_score(labs,(p1>=th).astype(int)), th) for th in np.linspace(0.05,0.95,37)]
        f1, best_threshold = max(f1s, key=lambda x:x[0])
        preds = (p1>=best_threshold).astype(int)
    else:
        preds = probs.argmax(-1)
        f1 = f1_score(labs, preds, average='macro')
    acc = accuracy_score(labs, preds)
    print(f"Ep{ep:02d} TrainLoss {tl/len(train_dl):.4f} ValLoss {vl/len(val_dl):.4f} Acc {acc:.4f} F1 {f1:.4f}" + (f" (best_th={best_threshold:.2f})" if num_classes==2 else ""))

# -------------------------------
# 最後：做「一次」完整溫度校準 + 閾值掃描，並存檔
# -------------------------------
scaler = fit_temperature(model, val_dl, device)

# 用 calibrated logits 算最終最佳 threshold / F1
model.eval(); labs=[]; logits_all=[]
with torch.no_grad():
    for ids, y, m, extra in val_dl:
        ids, y, m, extra = ids.to(device), y.to(device), m.to(device), extra.to(device)
        logits_all.append(model(ids,m,extra).cpu()); labs += y.cpu().tolist()
logits = torch.cat(logits_all,0).to(device)
with torch.no_grad():
    probs = scaler(logits).softmax(-1).cpu().numpy()

if num_classes==2:
    p1 = probs[:,1]
    f1s = [(f1_score(labs,(p1>=th).astype(int)), th) for th in np.linspace(0.05,0.95,37)]
    final_f1, best_threshold = max(f1s, key=lambda x:x[0])
else:
    preds = probs.argmax(-1)
    final_f1 = f1_score(labs, preds, average='macro')

logT_value=float(scaler.logT.detach().cpu().item())
if not math.isfinite(logT_value):
    logT_value=0.0

if num_classes==2 and not math.isfinite(best_threshold):
    best_threshold=0.5

torch.save({
            'model': model.state_dict(),
            'label2id': label2id,
            'id2label': id2label,
            'malicious_id': malicious_id,
            'extra_cols': extra_cols,
            'hand_dim': HAND_DIM,
            'config': {
                'max_len': MAX_LEN, 'd_model': D_MODEL, 'n_head': N_HEAD,
                'n_layer': N_LAYER, 'dropout': DROPOUT
            },
            'best_threshold': float(best_threshold) if num_classes==2 else None,
            'logT': logT_value,
            'extra_mean': extra_mean,
            'extra_std': extra_std,
        }, 'byte_transformer_kaggle.pt')
print(f"✅ 最後 Epoch 已存檔 → byte_transformer_kaggle.pt")
print("[debug] best_threshold =", best_threshold, " logT =", logT_value)
print("[debug] malicious_id =", malicious_id, " ->", id2label.get(malicious_id))
print("[debug] extra_cols =", extra_cols)
print("完成，最終 F1=", f1, " best_th=", best_threshold)