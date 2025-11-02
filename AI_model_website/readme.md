# app_kaggle.py(程式碼可改)
## 目標
1. 接收前端指令
2. 先進行AI判斷
3. 通過的MQTT訊息發送到target device
4. 接收 target device 的回報(ACK/OUTPUT/CRASH)
5. 我沒有實際連上MQTT，這部分可能請你測試一下
## Gateway
- GET/
    - 貼payload看p(malicious)
- GET/mqtt
    - 顯示MQTT/OUTPUT
- GET/events
    - 事件訊息
- POST /api/ infer
    - AI判斷(200: pass, 406: block)
- POST /api/send_to_device
    - AI通過傳給MQTT(202: pass, 406: block)
## 提醒
- 記得更改預設的MQTT_HOST與MQTT_PORT
- 啟動網站後
``` bash
 MQTT connected: 0 。代表已連上 broker
 Running on http://127.0.0.1:5000 and http://<你的IP>:5000
```
## MQTT Topic與JSON
*api_send_to_device有可能要改寫*
- Web -> Device:  
    - pipeline/forward/{device_id}
- Device -> Web
    - device/{device_id}/ack
    - device/{device_id}/output
    - device/{device_id}/crash
- Forward(website -> device)範例
```json
{
  "req_id": "uuid-string",
  "payload": { "cmd": "echo", "text": "hello" },  // 或 {"cmd":"run_cmd","command":"ADD 7 8"}...
  "exec_hint": { "timeout_ms": 5000 }
}
```
- response
```json
{ "req_id": "uuid", "status": "received" }

{ "req_id": "uuid", "status": "ok", "stdout": "<字串或JSON>" }

{ "req_id": "uuid", "status": "crash", "msg": "parse_error" }

```
- 打開 "http://\<server>:5000/mqtt"即時看response

- 接下來是Wfuzz的部分