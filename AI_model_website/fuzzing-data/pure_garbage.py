import random
import string

filename = "pure_garbage.jsonl"

# Define character pool for garbage (all printable symbols: !@#$%^&*...)
chaos_chars = string.ascii_letters + string.digits + string.punctuation + " "

print(f"Generating {filename} (pure garbage)...")

with open(filename, "w", encoding="utf-8") as f:
    for i in range(1000):
        # Determine the length of this line
        # 95% probability: normal length (10 ~ 300 characters)
        # 5% probability: extra long garbage (1000 ~ 5000 characters, for buffer testing)
        if random.random() < 0.05:
            length = random.randint(1000, 5000)
        else:
            length = random.randint(10, 300)
            
        # Generate garbage string
        garbage_line = ''.join(random.choices(chaos_chars, k=length))
        
        # Write to file
        f.write(garbage_line + "\n")

print(f"Done! Generated {filename}")