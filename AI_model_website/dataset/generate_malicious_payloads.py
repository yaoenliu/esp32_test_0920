# build_dataset_all_in_one.py
import csv
import random
import os
from sklearn.model_selection import train_test_split

# ====== 可自行調整的數量參數 ======
N_BENIGN_MATH = 40000
N_BENIGN_ECHO = 30000
N_BENIGN_PLAIN_ECHO = 30000
N_BENIGN_TEMP = 20000

N_BAD_PER_TYPE = 12000   # 每一種惡意型態的數量

TRAIN_RATIO = 0.8
SEED = 42
OUT_DIR = "dataset"

random.seed(SEED)

# ==============================
# 良性資料
# ==============================
def gen_benign():
    rows = []

    # run_cmd ADD / SUB
    for _ in range(N_BENIGN_MATH):
        a = random.randint(-1000, 1000)
        b = random.randint(-1000, 1000)
        op = random.choice(["ADD", "SUB"])
        rows.append([f"run_cmd,{op} {a} {b}", "benign", "math"])

    # run_cmd echo
    texts = [
        "hello world",
        "device ready",
        "system ok",
        "temperature normal",
        "abc123",
        "done"
    ]
    for _ in range(N_BENIGN_ECHO):
        t = random.choice(texts)
        rows.append([f"run_cmd,echo {t}", "benign", "echo"])

    # echo,
    for _ in range(N_BENIGN_PLAIN_ECHO):
        t = random.choice(texts)
        rows.append([f"echo,{t}", "benign", "echo"])

    # start_temp_report
    for _ in range(N_BENIGN_TEMP):
        v = random.choice(["1", "5", "10", "60", "abc", "xyz"])
        rows.append([f"start_temp_report,{v}", "benign", "temp"])

    return rows


# ==============================
# 惡性資料
# ==============================
def gen_bad_run_cmd_add_sub():
    rows = []

    # 參數數量錯
    for _ in range(N_BAD_PER_TYPE):
        a, b, c = random.randint(-100, 100), random.randint(-100, 100), random.randint(-100, 100)
        rows.append([f"run_cmd,ADD {a} {b} {c}", "malicious", "cmd_parse_error"])
        rows.append([f"run_cmd,SUB {a} {b} {c}", "malicious", "cmd_parse_error"])

    # 非整數
    bad_tokens = ["X", "abc", "1.5", "NaN"]
    for _ in range(N_BAD_PER_TYPE):
        a = random.randint(-100, 100)
        x = random.choice(bad_tokens)
        rows.append([f"run_cmd,ADD {a} {x}", "malicious", "cmd_parse_error"])
        rows.append([f"run_cmd,SUB {a} {x}", "malicious", "cmd_parse_error"])

    # op 拼錯
    wrong_ops = ["AD", "SU", "ADDd", "PLUS", "SUM", "SUBB"]
    for _ in range(N_BAD_PER_TYPE):
        a, b = random.randint(-100, 100), random.randint(-100, 100)
        op = random.choice(wrong_ops)
        rows.append([f"run_cmd,{op} {a} {b}", "malicious", "cmd_parse_error"])

    return rows


def gen_bad_run_cmd_echo():
    rows = []
    inj = [
        "hello; rm -rf /",
        "status | cat /etc/passwd",
        "ping 8.8.8.8 && reboot",
        "user `whoami`",
        "ok && echo hacked",
    ]
    for _ in range(N_BAD_PER_TYPE):
        p = random.choice(inj)
        rows.append([f"run_cmd,echo {p}", "malicious", "cmdi"])
    return rows


def gen_bad_echo():
    rows = []
    inj = [
        "hi && shutdown now",
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "name=$USER; id",
        "value > /tmp/leak",
    ]
    for _ in range(N_BAD_PER_TYPE):
        p = random.choice(inj)
        rows.append([f"echo,{p}", "malicious", "cmdi"])
    return rows


def gen_bad_start_temp_report():
    rows = []
    bad_vals = ["abc", "1.5", "-3", "NaN", "0", "-1"]
    for _ in range(N_BAD_PER_TYPE):
        v = random.choice(bad_vals)
        rows.append([f"start_temp_report,{v}", "malicious", "temp_error"])
    return rows


def gen_bad_misspelled_cmd():
    rows = []
    cmds = ["run", "rn_cmd", "ech", "eco", "runcmd"]
    for _ in range(N_BAD_PER_TYPE):
        a, b = random.randint(-50, 50), random.randint(-50, 50)
        c = random.choice(cmds)
        rows.append([f"{c},ADD {a} {b}", "malicious", "cmd_parse_error"])
    return rows


def gen_malicious():
    rows = []
    rows += gen_bad_run_cmd_add_sub()
    rows += gen_bad_run_cmd_echo()
    rows += gen_bad_echo()
    rows += gen_bad_start_temp_report()
    rows += gen_bad_misspelled_cmd()
    return rows


# ==============================
# 主流程
# ==============================
def main():
    benign = gen_benign()
    malicious = gen_malicious()

    print(f"[info] benign: {len(benign)}")
    print(f"[info] malicious: {len(malicious)}")

    all_rows = benign + malicious
    random.shuffle(all_rows)

    train, test = train_test_split(
        all_rows,
        train_size=TRAIN_RATIO,
        random_state=SEED,
        stratify=[r[1] for r in all_rows],
    )

    os.makedirs(OUT_DIR, exist_ok=True)

    for name, rows in [("train", train), ("test", test)]:
        path = f"{OUT_DIR}/{name}.csv"
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["payload", "label", "type"])
            w.writerows(rows)
        print(f"[ok] wrote {path} ({len(rows)})")


if __name__ == "__main__":
    main()
