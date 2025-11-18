import json
import random
import string

filename = "mix_test_data.jsonl"

# === 1. Define valid format generators ===
def gen_run_cmd():
    return {"cmd": "run_cmd", "command": f"ADD {random.randint(0,99)} {random.randint(0,99)}"}

def gen_echo():
    return {"cmd": "echo", "text": f"Hello {random.randint(1,999)}"}

def gen_db():
    return {"cmd": "db_query", "query": "SELECT * FROM users"}

def gen_temp():
    return {"cmd": "start_temp_report", "interval": random.randint(1, 60)}

# === 2. Define completely random (Arbitrary) generator ===
def gen_arbitrary():
    data = {}
    # Randomly generate 1 to 5 keys
    num_keys = random.randint(1, 5)
    for _ in range(num_keys):
        # Random key name (e.g., "xkq_vz")
        key_len = random.randint(3, 8)
        key = ''.join(random.choices(string.ascii_lowercase, k=key_len))
        
        # Random value type (string, int, bool)
        val_type = random.choice(['str', 'int', 'bool'])
        if val_type == 'str':
            data[key] = ''.join(random.choices(string.ascii_letters, k=8))
        elif val_type == 'int':
            data[key] = random.randint(0, 10000)
        else:
            data[key] = random.choice([True, False])
    return data

# === 3. Define huge payload generator ===
def generate_huge_string():
    # Generate 2KB to 5KB random string
    length = random.randint(2000, 5000) 
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

print(f"Generating {filename} (with mixed formats and huge payloads)...")

with open(filename, "w", encoding="utf-8") as f:
    for i in range(1000):
        
        # A. Determine basic structure (randomly pick a format)
        choice = random.choice(["run_cmd", "echo", "db", "temp", "arbitrary", "arbitrary"]) 
        # "arbitrary" appears twice to increase random data ratio
        
        if choice == "run_cmd":
            data = gen_run_cmd()
        elif choice == "echo":
            data = gen_echo()
        elif choice == "db":
            data = gen_db()
        elif choice == "temp":
            data = gen_temp()
        else:
            data = gen_arbitrary()

        # B. 10% chance to inject "huge payload" (Stress Test)
        if random.random() < 0.10:
            huge_str = generate_huge_string()
            # Randomly decide to "overwrite existing field" or "add a junk field"
            if list(data.keys()) and random.random() < 0.5:
                # Overwrite an existing key
                target_key = random.choice(list(data.keys()))
                data[target_key] = huge_str
            else:
                # Add a huge_payload key
                data["bloat_data_overflow"] = huge_str

        # Write to file
        f.write(json.dumps(data) + "\n")

print(f"Done! Generated {filename}")