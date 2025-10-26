# make_device_dicts.py  —  CSV + SEEDS + (optional) FuzzDB  ⇒ dicts/*.txt & *.jsonsafe.txt
import csv, os, re, json, argparse
from pathlib import Path

# ===== 1) 輸入資料位置（有哪個就讀哪個） =====
CANDIDATES = [
    "payload_log_clean_train.csv",
    "payload_log_clean_test.csv",
    "/mnt/data/payload_log_clean_train.csv",
    "/mnt/data/payload_log_clean_test.csv",
]

# 如果欄位名不同，在這裡調
PAYLOAD_COLS = ["payload", "text", "raw"]
TYPE_COLS    = ["attack_type", "label", "type"]

OUT_DIR = Path("dicts"); OUT_DIR.mkdir(exist_ok=True)

# ===== 2) 裝置需求：分類規則 =====
CMD_FORBIDDEN = r"[|&;`$><]"  # 遇到即視為 cmdi
SQLI_HINTS    = r"(?:\bunion\b|\bsleep\s*\(|\bor\s+1=1\b|--|#|/\*|\bselect\b|\bdrop\b)"
PATH_HINTS    = r"(\.\./|%2e%2e/|etc/passwd|win\.ini|proc/self)"
XSS_HINTS     = r"(<script|onerror=|<svg|</style>|javascript:)"

def route(payload, atype=""):
    s = (payload or "").strip().lower()
    # 先看 attack_type（若標有 xss/sqli/path/cmd/temp）
    if "xss" in atype:  return "xss"
    if "sql" in atype:  return "sqli"
    if "travers" in atype or "lfi" in atype or "path" in atype: return "path"
    if "cmd" in atype or "command" in atype or "rce" in atype:  return "cmdi"
    if "temp" in atype or "dos" in atype:                     return "temp"
    # 否則用規則猜
    if re.search(CMD_FORBIDDEN, s): return "cmdi"
    if re.search(SQLI_HINTS, s):    return "sqli"
    if re.search(PATH_HINTS, s):    return "path"
    if re.search(XSS_HINTS, s):     return "xss"
    return "cmdi"  # 默認丟 cmdi（對裝置最敏感）

def normalize_line(s):
    s = str(s).replace("\r"," ").replace("\n"," ")
    s = re.sub(r"\s+", " ", s).strip()
    return s[:1024]

def json_escape_lines(src, dst):
    with open(src, "r", encoding="utf-8", errors="ignore") as fin, \
         open(dst, "w", encoding="utf-8") as fout:
        for line in fin:
            s = line.rstrip("\n")
            esc = json.dumps(s, ensure_ascii=False)[1:-1]  # 去掉首尾引號
            fout.write(esc + "\n")

# ===== 3) 從 CSV 讀取、分流 =====
buckets = {k:[] for k in ["xss","sqli","path","cmdi","temp"]}
seen    = {k:set() for k in buckets}

def pick_col(header, cands):
    for c in cands:
        if c in header: return c
    return None

def ingest_csv(paths):
    found_any = False
    for p in paths:
        if not os.path.exists(p): continue
        with open(p, newline="", encoding="utf-8", errors="ignore") as f:
            r = csv.DictReader(f)
            pc = pick_col(r.fieldnames, PAYLOAD_COLS)
            tc = pick_col(r.fieldnames, TYPE_COLS)
            if not pc:
                print(f"[skip] {p} 沒找到 payload 欄位"); continue
            print(f"[read] {p} (payload={pc}, type={tc})"); found_any = True
            for row in r:
                raw = str(row.get(pc,"") or "").strip()
                if not raw: continue
                key = route(raw, (row.get(tc,"") or ""))
                clean = normalize_line(raw)
                if clean and clean not in seen[key]:
                    seen[key].add(clean)
                    buckets[key].append(clean)
    if not found_any:
        print("[warn] 找不到 CSV，將只輸出內建種子與 FuzzDB（若提供）。")

# ===== 4) 內建精簡種子（補齊常見 case） =====
SEEDS = {
    "xss": [
        '<script>alert(1)</script>','"><svg onload=alert(1)>',
        '<img src=x onerror=alert(1)>','<svg/onload=confirm(1)>',
        '</style><script>alert(1)</script>'
    ],
    "sqli": [
        "' or 1=1 --","' or '1'='1","\") or sleep(3)#",
        "union select null--","'; drop table users; --","%27%20or%201%3D1%20--"
    ],
    "path": [
        "../../etc/passwd","..%2f..%2fetc/passwd","../../proc/self/environ",
        "/..;/..;/..;/etc/passwd","..%255c..%255cWindows\\win.ini"
    ],
    "cmdi": [
        "&& whoami","| ls /","; cat /etc/passwd","|| id","`id`","| sh -c 'id'"
    ],
    "temp": [
        '{"cmd":"start_temp_report","interval":0}',
        '{"cmd":"start_temp_report","interval":1}',
        '{"cmd":"start_temp_report","interval":-1}',
        '{"cmd":"start_temp_report","interval":"abc"}',
        '{"cmd":"start_temp_report"}'
    ],
}

def ingest_seeds():
    for k, v in SEEDS.items():
        for s in v:
            if s not in seen[k]:
                seen[k].add(s); buckets[k].append(s)

# ===== 5) FuzzDB：挑常用清單合併（可用參數覆寫） =====
# 預設選一些涵蓋度高又「不會太大」的檔（你可用 CLI 參數追加/覆寫）
FUZZDB_PICK = {
    "xss": [
        "attack/xss/xss-rsnake.txt",
        "attack/xss/xss-without-parentheses-non-alphanumeric",
    ],
    "sqli": [
        "attack/sql-injection/detect/xplatform.txt",
        "attack/sql-injection/Generic-SQLi.txt",
    ],
    "path": [
        "attack/lfi/LFI-gracefulsecurity-linux.txt",
        "attack/lfi/common.txt",
    ],
    "cmdi": [
        "attack/os-cmd-execution/OSCommandInjection.txt",
    ],
    # temp：FuzzDB 不含此類，跳過
}

def ingest_fuzzdb(base_dir: Path, extra_map: dict[str, list[str]]|None, limit_per_file: int):
    if not base_dir: return
    picks = dict(FUZZDB_PICK)
    if extra_map:
        # 允許用戶附加或覆寫
        for k, v in extra_map.items():
            if v is None: continue
            picks[k] = v

    for cat, rels in picks.items():
        for rel in rels:
            p = base_dir / rel
            if not p.exists():
                print(f"[fuzzdb] miss {p}")
                continue
            print(f"[fuzzdb] + {cat}: {p}")
            try:
                with open(p, "r", encoding="utf-8", errors="ignore") as fin:
                    n = 0
                    for line in fin:
                        if limit_per_file and n >= limit_per_file: break
                        s = normalize_line(line)
                        if not s: continue
                        # 有些 FuzzDB 行本來就是 JSON/多欄，對我們先保留原字串
                        if s not in seen[cat]:
                            seen[cat].add(s); buckets[cat].append(s)
                            n += 1
            except Exception as e:
                print(f"[fuzzdb] read error {p}: {e}")

# ===== 6) 基於 AI 的擾動：簡單變體擴充 =====
def variants(items, max_size=500):
    out=set()
    for s in items:
        out.add(s)
        # URL encode 一版（只做少量）
        enc = s.replace("/", "%2f").replace(".", "%2e").replace(" ", "%20")
        out.add(enc)
        # 混大小寫（對英文字母）
        out.add("".join(c.upper() if i%2 else c.lower() for i,c in enumerate(s)))
        # 插入空白
        out.add(re.sub(r"([=/;|&])", r" \1 ", s))
    lst = list(out)
    return lst[:max_size] if max_size else lst

# ===== 7) 主程式 =====
def main():
    ap = argparse.ArgumentParser(description="Build device-aware fuzz dictionaries")
    ap.add_argument("--fuzzdb-dir", type=str, default=None, help="path to fuzzdb root (optional)")
    ap.add_argument("--fuzzdb-limit", type=int, default=800, help="max lines to take per fuzzdb file")
    ap.add_argument("--no-variants", action="store_true", help="disable auto variants")
    # 自訂覆寫 FuzzDB 檔列表（逗號分隔，相對於 fuzzdb 根目錄）
    ap.add_argument("--xss-files",  type=str, default=None)
    ap.add_argument("--sqli-files", type=str, default=None)
    ap.add_argument("--path-files", type=str, default=None)
    ap.add_argument("--cmdi-files", type=str, default=None)
    args = ap.parse_args()

    ingest_csv(CANDIDATES)
    ingest_seeds()

    extra_map = None
    fzdir = Path(args.fuzzdb_dir) if args.fuzzdb_dir else None
    if fzdir:
        extra_map = {
            "xss":  args.xss_files.split(",")  if args.xss_files  else None,
            "sqli": args.sqli_files.split(",") if args.sqli_files else None,
            "path": args.path_files.split(",") if args.path_files else None,
            "cmdi": args.cmdi_files.split(",") if args.cmdi_files else None,
        }
        ingest_fuzzdb(fzdir, extra_map, args.fuzzdb_limit)

    # 變體（xss/sqli/path/cmdi）
    if not args.no_variants:
        for k in ["xss","sqli","path","cmdi"]:
            buckets[k] = variants(buckets[k], max_size=800)

    # 輸出：原始 + JSON-safe
    for name, lines in buckets.items():
        raw_path = OUT_DIR / f"{name}.txt"
        with open(raw_path, "w", encoding="utf-8") as f:
            for s in lines: f.write(s + "\n")
        jsonsafe = OUT_DIR / f"{name}.jsonsafe.txt"
        json_escape_lines(raw_path, jsonsafe)

    print("完成！輸出在 ./dicts：")
    for f in sorted(OUT_DIR.glob("*")):
        print(" -", f)

if __name__ == "__main__":
    main()
