import json
import random

filename = "temp_cmd_test_data.jsonl"

# Define extra fields (simulate IoT device communication)
extra_keys_pool = ["unit", "sensor_id", "request_id", "duration", "target_ip"]

print(f"Generating {filename} ...")

with open(filename, "w", encoding="utf-8") as f:
    for i in range(1000):
        data = {}
        
        # 50% probability for valid data
        is_valid = random.random() < 0.5
        
        if is_valid:
            # === Valid ===
            data["cmd"] = "start_temp_report"
            # interval set to integer between 1~60 seconds
            data["interval"] = random.randint(1, 60)
            
            # Randomly add 0~3 extra fields
            num_extras = random.randint(0, 3)
            for _ in range(num_extras):
                k = random.choice(extra_keys_pool)
                if k == "unit":
                    data[k] = random.choice(["C", "F"])
                elif k == "sensor_id":
                    data[k] = f"sns_{random.randint(100, 999)}"
                else:
                    data[k] = random.randint(1000, 9999)
                
        else:
            # === Invalid (structure break) ===
            temp_data = {
                "cmd": "start_temp_report",
                "interval": random.randint(1, 60),
                "junk_flag": True # Marker
            }
            
            remove_choice = random.choice(["no_cmd", "no_interval", "no_both"])
            
            if remove_choice == "no_cmd":
                del temp_data["cmd"]
            elif remove_choice == "no_interval":
                del temp_data["interval"]
            elif remove_choice == "no_both":
                del temp_data["cmd"]
                del temp_data["interval"]
                # Insert completely irrelevant data
                temp_data["error"] = "empty_payload"
            
            data = temp_data

        # Write to file
        f.write(json.dumps(data) + "\n")

print(f"Done! Generated {filename}")