import json
import random
import time

filename = "run_cmd_test_data.jsonl"

# Define basic command operations to make data more realistic
ops = ["ADD", "SUB", "MUL", "DIV", "ECHO"]

# Define extra random keys (simulate adding keys)
extra_keys_pool = ["timestamp", "msg_id", "priority", "source", "retry_count"]

def generate_random_command():
    op = random.choice(ops)
    if op == "ECHO":
        return f"ECHO 'Hello {random.randint(1, 100)}'"
    else:
        return f"{op} {random.randint(0, 100)} {random.randint(0, 100)}"

print(f"Generating {filename} ...")

with open(filename, "w", encoding="utf-8") as f:
    for i in range(1000):
        data = {}
        
        # Determine if this is "standard compliant" data (50% probability)
        is_valid = random.random() < 0.5
        
        if is_valid:
            # === Case A: Standard compliant (must have cmd, command) ===
            data["cmd"] = "run_cmd"
            data["command"] = generate_random_command()
            
            # Randomly add keys (0 ~ 3 extra fields)
            num_extras = random.randint(0, 3)
            for _ in range(num_extras):
                key = random.choice(extra_keys_pool)
                data[key] = random.randint(1, 9999) if key != "timestamp" else time.time()
                
        else:
            # === Case B: Abnormal data (reduced keys or missing required fields) ===
            # First create a complete one
            temp_data = {
                "cmd": "run_cmd",
                "command": generate_random_command()
            }
            # Also randomly add some noise keys
            if random.choice([True, False]):
                temp_data["noise_data"] = "random_string"

            # Randomly break structure (reduce keys)
            # 1. Remove cmd
            # 2. Remove command
            # 3. Remove both (only noise keys remain)
            remove_choice = random.choice(["no_cmd", "no_command", "no_both"])
            
            if remove_choice == "no_cmd":
                del temp_data["cmd"]
            elif remove_choice == "no_command":
                del temp_data["command"]
            elif remove_choice == "no_both":
                del temp_data["cmd"]
                del temp_data["command"]
                # Ensure not empty object, insert a random one
                temp_data["unknown_key"] = "junk_data"
            
            data = temp_data

        # Write to file (JSON Lines format, one JSON per line)
        f.write(json.dumps(data) + "\n")

print("Done! Generated 1000 lines of JSON test data.")