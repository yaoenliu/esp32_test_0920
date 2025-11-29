import random
import string

SAFE_ECHO = [
    "hello", "ok", "system ok", "ready", "done" "device ready",
    "normal", "upload ok", "cpu good", "ram good",
]

MAL_ECHO = [
    "a;rm -rf /", "x|cat /etc/passwd", "b > /tmp/out",
    "<script>alert(1)</script>", "<img src=x onerror=1>",
]

NON_INT_VALUES = ["X", "abc", "NaN", "1.2", "-3.7", "xx8y", "0xGG"]

def rstr(n=10):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(n))

def gen_run_cmd_add_sub():
    cases = []

    # ------ 良性 ADD (2 args) ------
    for _ in range(2000):
        a = random.randint(-3000, 3000)
        b = random.randint(-3000, 3000)
        cases.append(f"run_cmd,ADD {a} {b}")

    # ------ 良性 SUB ------
    for _ in range(2000):
        a = random.randint(-3000, 3000)
        b = random.randint(-3000, 3000)
        cases.append(f"run_cmd,SUB {a} {b}")

    # ------ 惡意：3~5 參數 ------
    for _ in range(1500):
        n_args = random.randint(3, 5)
        op = random.choice(["ADD", "SUB"])
        nums = " ".join(str(random.randint(-3000, 3000)) for _ in range(n_args))
        cases.append(f"run_cmd,{op} {nums}")

    # ------ 惡意：非整數 ------
    for _ in range(1500):
        op = random.choice(["ADD", "SUB"])
        a = random.choice(NON_INT_VALUES)
        b = random.randint(0, 100)
        cases.append(f"run_cmd,{op} {a} {b}")

    # ------ 惡意：0 / 1 參數 ------
    for _ in range(1000):
        op = random.choice(["ADD", "SUB"])
        if random.random() < 0.5:
            # 0 args
            cases.append(f"run_cmd,{op}")
        else:
            # 1 arg
            a = random.randint(-100, 100)
            cases.append(f"run_cmd,{op} {a}")

    return cases

def gen_payloads():
    cases = []

    # ADD / SUB 含惡意
    cases.extend(gen_run_cmd_add_sub())

    # benign run_cmd,echo
    for _ in range(3000):
        cases.append(f"run_cmd,echo {random.choice(SAFE_ECHO)}")

    # malicious run_cmd,echo
    for _ in range(2000):
        cases.append(f"run_cmd,echo {random.choice(MAL_ECHO)}")

    # benign echo
    for _ in range(3000):
        cases.append(f"echo,{random.choice(SAFE_ECHO)}")

    # malicious echo
    for _ in range(2000):
        cases.append(f"echo,{random.choice(MAL_ECHO)}")

    # start_temp_report
    for _ in range(3000):
        if random.random() < 0.7:
            cases.append(f"start_temp_report,{random.randint(-10, 200)}")
        else:
            cases.append(f"start_temp_report,{rstr(5)}")

    # Noise
    for _ in range(2000):
        noise = ''.join(random.choice(string.printable) for _ in range(20))
        cases.append(noise)

    random.shuffle(cases)
    return cases

if __name__ == "__main__":
    data = gen_payloads()
    with open("test_data.jsonl", "w", encoding="utf-8") as f:
        for line in data:
            f.write(line + "\n")
    print(f"[OK] 已建立 test_data.jsonl，共 {len(data)} 筆資料")
