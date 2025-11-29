# rewrite_dataset.py
# -*- coding: utf-8 -*-
import csv, re, os, sys, ast   # ← 多加 ast

IN_TRAIN = "dataset_new_train_with_malicious.csv"
IN_TEST  = "balanced_test.csv"
OUT_TRAIN = "dataset_new_train_malicious_label.csv"
OUT_TEST = "dataset_new_test.csv"

# ====== 規則設定 ======

SHELL_TOKENS = r'[|&;`$><\\]'              # 殼層關鍵字元(易產生 command injection)
XSS_HINTS   = r'(?i)(<script|onerror=|<svg|</style|<img\s+src=)'  # 粗略抓常見 XSS

def is_int(x: str) -> bool:
    try:
        int(x.strip())
        return True
    except:
        return False

def norm_ws(s: str) -> str:
    # 單純壓成單一空白，去頭尾
    return re.sub(r'\s+', ' ', s).strip()

def classify(payload_text: str):
    """
    輸入任意字串 payload_text，回傳：(normalized_payload, label, attack_type)
    若是你規定的新語法：start_temp_report / run_cmd / echo，會進一步驗證參數。
    否則就依內容特徵（殼層字元、XSS）粗略歸類，保留原 payload。
    """
    raw = payload_text.strip()
    s = raw

    # --- 嘗試 parse 你定義的三類命令 ---
    # 格式一：start_temp_report,<int>
    m = re.fullmatch(r'\s*start_temp_report\s*,\s*([+-]?\d+)\s*', s, flags=re.IGNORECASE)
    if m:
        interval = m.group(1)
        # 只要是整數就是 ok
        norm = f"start_temp_report,{int(interval)}"
        return (norm, "benign", "benign")

    # 如果寫成 start_temp_report, <不是整數>
    m = re.fullmatch(r'\s*start_temp_report\s*,\s*(.+?)\s*', s, flags=re.IGNORECASE)
    if m:
        # 非整數 → 錯誤
        bad = norm_ws(f"start_temp_report,{m.group(1)}")
        return (bad, "malicious", "temp_report_error")

    # 格式二：run_cmd,ADD a b 或 run_cmd,SUB a b
    m = re.fullmatch(r'\s*run_cmd\s*,\s*(ADD|SUB)\s+([+-]?\d+)\s+([+-]?\d+)\s*', s, flags=re.IGNORECASE)
    if m:
        op = m.group(1).upper()
        a, b = int(m.group(2)), int(m.group(3))
        norm = f"run_cmd,{op} {a} {b}"
        return (norm, "benign", "benign")

    # run_cmd, echo <文字>
   # run_cmd, echo <文字>（支援去除中括號）
    m = re.fullmatch(r'\s*run_cmd\s*,\s*echo\s+(.+)\s*', s, flags=re.IGNORECASE)
    if m:
        txt_raw = m.group(1).strip()

    # 若像 ['sensor','system'] → 解析成 list
        txt_norm = txt_raw
        if txt_norm.startswith("[") and txt_norm.endswith("]"):
            try:
                val = ast.literal_eval(txt_norm)
                if isinstance(val, (list, tuple)):
                    txt_norm = " ".join(str(x) for x in val)
            except Exception:
                txt_norm = norm_ws(txt_raw)
        else:
            txt_norm = norm_ws(txt_norm)

        norm = f"run_cmd, echo {txt_norm}"

    # 判斷惡意
        if re.search(SHELL_TOKENS, txt_raw):
            return (norm, "malicious", "cmdi")
        if re.search(XSS_HINTS, txt_raw):
            return (norm, "malicious", "xss")

        return (norm, "benign", "benign")
    # 類 run_cmd 但不合語法 → 看看是否出現殼層字元
    if s.lower().startswith("run_cmd"):
        if re.search(SHELL_TOKENS, s):
            return (norm_ws(s), "malicious", "cmdi")
        return (norm_ws(s), "malicious", "cmd_parse_error")

    # ⭐⭐ 格式三：echo, <文字>（有 [] / 沒 [] 都當同一種合法型態）
    m = re.fullmatch(r'\s*echo\s*,\s*(.+)\s*', s, flags=re.IGNORECASE)
    if m:
        txt_raw = m.group(1)           # echo 後面的原始內容
        txt_norm = txt_raw.strip()

        # 如果是像 ['sensor', 'status', 'report'] 這種 list，就轉成 "sensor status report"
        if txt_norm.startswith("[") and txt_norm.endswith("]"):
            try:
                val = ast.literal_eval(txt_norm)
                if isinstance(val, (list, tuple)):
                    txt_norm = " ".join(str(x) for x in val)
            except Exception:
                # parse 失敗就退回原始內容壓空白
                txt_norm = norm_ws(txt_raw)
        else:
            # 原本就不是 list → 壓空白就好
            txt_norm = norm_ws(txt_norm)

        norm = f"echo, {txt_norm}"

        # 惡意 / 良性判斷仍然用「原始內容 txt_raw」來看 XSS / shell 字元
        if re.search(XSS_HINTS, txt_raw):
            return (norm, "malicious", "xss")
        if re.search(SHELL_TOKENS, txt_raw):
            return (norm, "malicious", "cmdi")
        return (norm, "benign", "norm")

    # --- 舊格式：保守偵測 ---
    # 有 XSS 指標
    if re.search(XSS_HINTS, s):
        return (s, "malicious", "xss")

    # 有殼層字元（可視作 command injection）
    if re.search(SHELL_TOKENS, s):
        return (s, "malicious", "cmdi")

    # 其他不明格式：若你舊資料已有標籤可沿用；否則標成惡意(或改成 benign 也行)
    return (s, "malicious", "cmd_parse_error")


def load_csv_maybe_header(path):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, 'r', encoding='utf-8', newline='') as f:
        reader = csv.reader(f)
        head = next(reader, None)
        # 嘗試偵測是否有 header
        if head and any(h.lower() in ('payload','label','attack_type') for h in head):
            # 有 header：找 payload 欄
            idx = head.index('payload') if 'payload' in head else 0
            for r in reader:
                if not r: continue
                rows.append(r[idx])
        else:
            # 無 header：第一列就是資料
            if head: rows.append(head[0] if head else "")
            for r in reader:
                if not r: continue
                rows.append(r[0])
    return rows


def write_dataset(path, items):
    # items 是 list[(payload,label,attack_type)]
    with open(path, 'w', encoding='utf-8', newline='') as f:
        w = csv.writer(f)
        w.writerow(['payload','label','attack_type'])
        w.writerows(items)


def process(in_path, out_path):
    src = load_csv_maybe_header(in_path)
    out = []
    for p in src:
        norm, lbl, atype = classify(p)
        out.append((norm, lbl, atype))
    write_dataset(out_path, out)
    print(f"[ok] {in_path} -> {out_path}  共 {len(out)} 列")


if __name__ == "__main__":
    process(IN_TRAIN, OUT_TRAIN)
    process(IN_TEST, OUT_TEST)
