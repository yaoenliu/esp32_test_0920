import json
import random
import time

filename = "echo_test_data.jsonl"

# Random text generator
def generate_random_text():
    messages = ["Hello World", "System Check", "Ping", "Connection Established", "Data Packet", "Error Log"]
    msg = random.choice(messages)
    # Add random number to make content unique
    return f"{msg} {random.randint(1, 9999)}"

# Extra keys pool (simulate adding keys)
extra_keys_pool = ["timestamp", "msg_id", "source_ip", "priority", "region"]

print(f"Generating {filename} ...")

with open(filename, "w", encoding="utf-8") as f:
    for i in range(1000):
        data = {}
        
        # Determine if this is valid data (50% probability)
        is_valid = random.random() < 0.5
        
        if is_valid:
            # === Valid: Contains required fields ===
            data["cmd"] = "echo"
            data["text"] = generate_random_text()
            
            # [Add Key] Randomly add 0~3 extra fields
            num_extras = random.randint(0, 3)
            for _ in range(num_extras):
                key = random.choice(extra_keys_pool)
                # Assign some dummy values
                data[key] = int(time.time()) if key == "timestamp" else random.randint(100, 999)
                
        else:
            # === Invalid: Break structure (reduce keys) ===
            # First create basic structure
            temp_data = {
                "cmd": "echo",
                "text": generate_random_text(),
                "noise_data": "random_junk" # Intentionally add noise
            }
            
            # Randomly remove required fields
            remove_choice = random.choice(["no_cmd", "no_text", "no_both"])
            
            if remove_choice == "no_cmd":
                del temp_data["cmd"]
            elif remove_choice == "no_text":
                del temp_data["text"]
            elif remove_choice == "no_both":
                del temp_data["cmd"]
                del temp_data["text"]
                # Ensure not empty object, add an unknown key
                temp_data["unknown_protocol"] = "????"
            
            data = temp_data

        # Write to file
        f.write(json.dumps(data) + "\n")

print(f"Done! Generated {filename}")