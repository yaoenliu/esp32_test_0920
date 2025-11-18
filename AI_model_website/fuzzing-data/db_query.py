import json
import random
import time

filename = "db_query_test_data.jsonl"

# Simulate database operation commands
def generate_db_query():
    actions = ["SET", "GET", "DEL", "EXISTS"]
    keys = ["user", "admin", "session_id", "config_level", "score"]
    names = ["alice", "bob", "charlie", "dave", "eve", "root"]
    
    action = random.choice(actions)
    key = random.choice(keys)
    
    if action == "SET":
        # SET user alice
        value = random.choice(names) if key in ["user", "admin"] else random.randint(1, 1000)
        return f"{action} {key} {value}"
    elif action == "GET" or action == "DEL" or action == "EXISTS":
        # GET user
        return f"{action} {key}"

# Extra fields (simulate database request metadata)
extra_keys_pool = ["transaction_id", "auth_token", "timeout_ms", "shard_id", "retry"]

print(f"Generating {filename} ...")

with open(filename, "w", encoding="utf-8") as f:
    for i in range(1000):
        data = {}
        
        # 50% probability for valid data
        is_valid = random.random() < 0.5
        
        if is_valid:
            # === Valid ===
            data["cmd"] = "db_query"
            data["query"] = generate_db_query()
            
            # Randomly add 0~3 extra fields
            num_extras = random.randint(0, 3)
            for _ in range(num_extras):
                k = random.choice(extra_keys_pool)
                if k == "transaction_id":
                    data[k] = f"tx_{random.randint(10000, 99999)}"
                else:
                    data[k] = random.randint(1, 5000)
                
        else:
            # === Invalid (missing keys) ===
            temp_data = {
                "cmd": "db_query",
                "query": generate_db_query(),
                "malformed_flag": True # Mark this as corrupted data
            }
            
            remove_choice = random.choice(["no_cmd", "no_query", "no_both"])
            
            if remove_choice == "no_cmd":
                del temp_data["cmd"]
            elif remove_choice == "no_query":
                del temp_data["query"]
            elif remove_choice == "no_both":
                del temp_data["cmd"]
                del temp_data["query"]
                temp_data["error_log"] = "unexpected_payload"
            
            data = temp_data

        # Write to file
        f.write(json.dumps(data) + "\n")

print(f"Done! Generated {filename}")