# make_device_dicts.p
## 字典
- xss:
    - 對應echo
- sqli:
    - 對應db_query
- cmdi:
    - 對應run_cmd
- temp:
    - 對應溫度感測器
- 我的AI目前對於cmdi的感測能力較弱，可以優先測
- temp的內容我並沒有放到dataset裡面，AI應該會炸，等wfuzz之後我再重新train
*優先使用jsonsave.txt，雖然原始檔案和jsonsave應該差不多*

## 啟動網站
```bash
# 看到:
# * Running on http://127.0.0.1:5000
# * Running on http://<你的IP>:5000
# Console 會顯示: MQTT connected: <rc> 並訂閱 device/+/ack|output|crash
```
## 用字典fuzz
- 只測AI放行+device的錯誤訊息，下面提供範例，我只要看device有沒有炸
```bash
wfuzz -t 10 --req-delay 0.05 \
  -z file,dicts/cmdi.jsonsafe.txt \
  -H "Content-Type: application/json" \
  -d '{"device_id":"esp-lab-01","payload":"FUZZ"}'\
  --sc 202 --ss '"status":"crash"' \
  http://<server>:5000/api/send_to_device
```
- pipeline/forward/{device_id}範例收到json訊息
```json
{
  "req_id": "xxxx",
  "payload": "ADD 7 8"      // 或物件：{"cmd":"echo","text":"hello"}
  ,"exec_hint": {"timeout_ms": 5000}
}
```
- ack
```json
{"req_id":"xxxx","status":"ok","msg":"received"}
```
- output(success)
```json
{"req_id":"xxxx","status":"ok","stdout":"15"}
```
- output(error)
```json
{"req_id":"xxxx","status":"crash","msg":"cmd_parse_error"}
```
## 執行wfuzz
- 安裝完wfuzz後打整條鏈/api/send_to_device看裝置回報(提供範例可改)
- 看target device
``` bash
wfuzz -t 10 --req-delay 0.05 `
  -z file,dicts\cmdi.jsonsafe.txt `
  -H 'Content-Type: application/json' `
  -d '{"device_id":"esp-lab-01","payload":"FUZZ"}' `
  --sc 202 --ss '"status":"crash"' `
  http://127.0.0.1:5000/api/send_to_device
```
- 看AI
```bash
wfuzz -t 10 --req-delay 0.05 \
  -z file,dicts\sqli.jsonsafe.txt \
  -H 'Content-Type: application/json' \
  -d '{"payload":"FUZZ","mode":"th"}' \
  --sc 200 http://127.0.0.1:5000/api/infer
```

## 總結
> 我沒有把[FuzzDB](https://github.com/fuzzdb-project/fuzzdb)的字典詳細測試於AI上，我只抓一部分測試(各檔案約100行)，我的AI並沒有把全部的字典都擋下來，主要是看target device有沒有產生crash，若有的話請你幫我記錄一下

- 惡意訊息會讓target device crash的請幫我紀錄於Wfuzz的資料夾並命名crash.csv(欄位名稱要跟payload_log_clean_test.csv一樣)，我之後再把它們加進payload_log_clean_train裡面讓AI學習
    - 能幫我把惡意訊息弄成payload的形式是最好，這樣我可以直接丟給AI，不用再做前處理