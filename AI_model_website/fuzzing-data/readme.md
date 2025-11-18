# fuzzing data
using python generate test_data.jsonl
and then use wfuzz
```bash

wfuzz  -z file,<file_path>/test_data.jsonl -H "Content-Type: application/json" -d '{"device_id":"esp-lab-01","payload":"FUZZ"}'  --sc 202 --ss '"status":"crash"' -c <hsot_ip>:5000/api/send_to_device
```