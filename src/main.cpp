#include <Arduino.h>
#include <ArduinoJson.h>
#include <PubSubClient.h>
#include <WiFi.h>
#include "db.h"
#include "conf.h"

// Wifi 連線
WiFiClient espClient;
// MQTT 客戶端
PubSubClient client(espClient);

// 定義禁止使用的字元
const char *FORBIDDEN_CHARS = "|&;`$><";
// 定義允許的指令
// const char *ALLOWED_INSTRUCTIONS[] = {"ADD", "ECHO"};

// 函式原型宣告
void handleRunCmd(String command);
void handleEchoCmd(String text);
void handleDb_queryCmd(String query);
void handleTempreportCmd(bool enable, u8_t interval);

void sendErrorResponse(const char *msg);
void sendOkResponse(const String &stdoutMsg);
void sendTempReport(TimerHandle_t xTimer);

void callback(char *topic, byte *payload, unsigned int length);
void reconnect();

TimerHandle_t tempReportTimer;

void setup()
{
    // 啟動序列埠，設定鮑率為 115200
    Serial.begin(115200);
    while (!Serial)
    {
        ; // 等待序列埠連接
    }

    WiFi.begin(ssid.c_str(), password.c_str());
    Serial.println("Connecting to WiFi...");
    while (WiFi.status() != WL_CONNECTED)
    {
        delay(500);
        Serial.print(".");
    }
    Serial.println("\nWiFi connected successfully!");
    Serial.print("IP address: ");
    Serial.println(WiFi.localIP());

    client.setServer(mqtt_server.c_str(), 1883);
    client.setCallback(callback);
}

void loop()
{
    if (!client.connected())
    {
        reconnect();
    }
    client.loop();
    return;
    // 如果序列埠有可讀取的資料
    if (Serial.available() > 0)
    {
    }
}
void processMessage(String jsonString)
{
    jsonString.trim(); // 去除前後空白

    // 建立一個 JsonDocument 來解析輸入的 JSON
    // 以動態分配方式創建文件（ArduinoJson v7 建議使用 JsonDocument）
    JsonDocument payload;

    // 進行反序列化 (解析 JSON 字串)
    DeserializationError error = deserializeJson(payload, jsonString);

    // 檢查解析是否成功
    if (error)
    {
        sendErrorResponse("json_decode_error");
        return;
    }

    // 檢查必要的鍵是否存在且格式正確
    if (!payload.containsKey("cmd") || !payload["cmd"].is<String>())
    {
        sendErrorResponse("invalid_payload");
        return;
    }

    // 取得 cmd 的值
    const char *ccmd = payload["cmd"];
    String cmd = String(ccmd);
    // 判斷 cmd 是否為 "run_cmd"
    if (cmd == "run_cmd")
    {
        Serial.println("Processing run_cmd...");
        if (!payload.containsKey("command") || !payload["command"].is<String>())
        {
            sendErrorResponse("invalid_command_format");
            return;
        }
        String commandStr = String(payload["command"].as<String>());
        Serial.println("Received command: " + commandStr);
        handleRunCmd(commandStr);
    }
    else if (cmd == "db_query")
    {
        Serial.println("Processing db_query...");
        if (!payload.containsKey("query") || !payload["query"].is<String>())
        {
            sendErrorResponse("invalid_query_format");
            return;
        }
        String queryStr = String(payload["query"].as<String>());
        handleDb_queryCmd(queryStr);
    }
    else if (cmd == "echo")
    {
        Serial.println("Processing echo...");
        if (!payload.containsKey("text") || !payload["text"].is<String>())
        {
            sendErrorResponse("invalid_text_format");
            return;
        }
        String messageStr = String(payload["text"].as<String>());
        handleEchoCmd(messageStr);
    }
    else if (cmd == "start_temp_report")
    {
        Serial.println("Processing tempreport...");
        if (!payload.containsKey("interval") || !payload["interval"].is<u8_t>())
        {
            sendErrorResponse("invalid_interval_format");
            return;
        }
        u8_t interval = payload["interval"].as<u8_t>();
        handleTempreportCmd(true, interval);
    }
    else if (cmd == "stop_temp_report")
    {
        Serial.println("Processing stop_temp_report...");
        handleTempreportCmd(false, 0);
    }
    else
    {
        Serial.println("Unknown command");
        sendErrorResponse("unknown_cmd");
    }
}

void handleRunCmd(String command)
{
    // 1. 安全檢查：檢查是否包含惡意字元
    for (int i = 0; FORBIDDEN_CHARS[i] != '\0'; i++)
    {
        if (command.indexOf(FORBIDDEN_CHARS[i]) != -1)
        {
            sendErrorResponse("cmd_parse_error");
            return;
        }
    }

    command.trim(); // 清除前後空白

    int firstSpace = command.indexOf(' ');
    if (firstSpace == -1)
    {
        // 缺少參數，格式錯誤
        sendErrorResponse("cmd_parse_error");
        return;
    }

    String instruction = command.substring(0, firstSpace);
    instruction.toUpperCase(); // 轉換為大寫以方便比對

    // 只處理 ADD 指令
    if (instruction == "ADD")
    {
        // 找到第二個空格，分離出兩個參數
        int secondSpace = command.indexOf(' ', firstSpace + 1);
        if (secondSpace == -1)
        {
            // 只有一個參數，格式錯誤
            sendErrorResponse("cmd_parse_error");
            return;
        }

        // 提取兩個參數的字串
        String arg1_str = command.substring(firstSpace + 1, secondSpace);
        String arg2_str = command.substring(secondSpace + 1);

        // 將參數字串轉換為數字
        // String.toInt() 如果轉換失敗會回傳 0
        long num1 = arg1_str.toInt();
        long num2 = arg2_str.toInt();

        // 一個簡易的檢查，判斷轉換是否真的成功
        // 如果字串不是 "0" 但轉換結果是 0，表示轉換失敗
        if ((num1 == 0 && arg1_str != "0") || (num2 == 0 && arg2_str != "0"))
        {
            sendErrorResponse("cmd_parse_error");
            return;
        }

        long result = num1 + num2;
        sendOkResponse(String(result));
    }

    else if (instruction == "ECHO")
    {
        // 提取要回傳的訊息
        String message = command.substring(firstSpace + 1);
        sendOkResponse(message);
    }

    else
    {
        // 任何未知的指令都視為解析錯誤
        sendErrorResponse("cmd_parse_error");
    }
}

void handleEchoCmd(String text)
{
    // 與 ECHO 指令相同，直接回傳訊息
    sendOkResponse(text);
}

void handleDb_queryCmd(String query)
{
    query.trim(); // 清除前後空白

     if (query == "RESET")
    {
        removeAll();
        sendOkResponse("DB_RESET_done");
        return;
    }
    else if (query == "DUMP")
    {
        JsonDocument allData = listAll();
        String output;
        serializeJson(allData, output);
        sendOkResponse(output);
        return;
    }

    int firstSpace = query.indexOf(' ');
    if (firstSpace == -1)
    {
        // 缺少參數，格式錯誤
        sendErrorResponse("cmd_parse_error");
        return;
    }
    String instruction = query.substring(0, firstSpace);
    String key_value = query.substring(firstSpace + 1);

    if (instruction == "SET")
    {
        firstSpace = key_value.indexOf(' ');
        if (firstSpace == -1)
        {
            // 缺少參數，格式錯誤
            sendErrorResponse("cmd_parse_error");
            return;
        }
        String key = key_value.substring(0, key_value.indexOf(' '));
        String value = key_value.substring(key_value.indexOf(' ') + 1);

        if (key.length() == 0 || value.length() == 0)
        {
            sendErrorResponse("cmd_parse_error");
            return;
        }
        saveData(key, value);
        sendOkResponse("Data saved");
    }
    else if (instruction == "GET")
    {
        String key = query.substring(firstSpace + 1);
        String value = getData(key);
        sendOkResponse(value);
    }
    else if (instruction == "RESET")
    {
        removeAll();
    }
    else
    {
        sendErrorResponse("cmd_parse_error");
    }
}

void handleTempreportCmd(bool enable, u8_t interval)
{
    if (!enable)
    {
        // 停止溫度報告
        if (tempReportTimer != NULL)
        {
            xTimerStop(tempReportTimer, 0);
            xTimerDelete(tempReportTimer, 0);
            tempReportTimer = NULL;
        }
        sendOkResponse("Temperature reporting stopped");
        return;
    }
    // 這裡可以加入啟動溫度報告的邏輯
    if (interval < 2)
    {
        sendErrorResponse("invalid_interval");
        return;
    }
    String responseMsg = "Temperature reporting started with interval: " + String(interval);
    if(tempReportTimer != NULL)
    {
        xTimerStop(tempReportTimer, 0);
        xTimerDelete(tempReportTimer, 0);
        tempReportTimer = NULL;
    }
    tempReportTimer = xTimerCreate("TempReportTimer", pdMS_TO_TICKS(interval * 1000), pdTRUE, NULL, sendTempReport);

    xTimerStart(tempReportTimer, 0);

    sendOkResponse(responseMsg);
}

void sendErrorResponse(const char *msg)
{
    JsonDocument responseDoc;
    responseDoc["status"] = "crash";
    responseDoc["msg"] = msg;

    String output;
    serializeJson(responseDoc, output);
    client.publish(topic_crash.c_str(), output.c_str());
    Serial.println(output);
}

void sendOkResponse(const String &stdoutMsg)
{
    JsonDocument responseDoc;
    responseDoc["status"] = "ok";
    responseDoc["stdout"] = stdoutMsg;

    String output;
    serializeJson(responseDoc, output);
    client.publish(topic_output.c_str(), output.c_str());
    Serial.println(output);
}

void sendTempReport(TimerHandle_t xTimer)
{
    JsonDocument reportDoc;
    reportDoc["status"] = "ok";
    reportDoc["sensor"] = "temp";
    reportDoc["value"] = random(20, 30); // 模擬溫度值，實際應從感測器讀取
    String output;
    serializeJson(reportDoc, output);
    client.publish(topic_output.c_str(), output.c_str());
    Serial.println(output);
}

// ========== MQTT 回呼 ==========
void callback(char *topic, byte *payload, unsigned int length)
{
    String lastMessage = "";
    for (unsigned int i = 0; i < length; i++)
    {
        lastMessage += (char)payload[i];
    }
    Serial.printf("Received message from topic [%s]: %s\n", topic, lastMessage.c_str());
    client.publish(topic_ack.c_str(), lastMessage.c_str());
    processMessage(lastMessage);
}

// ========== 嘗試連線 MQTT ==========
void reconnect()
{
    while (!client.connected())
    {
        Serial.print("Attempting MQTT connection...");
        String clientId = "ESP32Client-" + String(random(0xffff), HEX);
        if (client.connect(clientId.c_str()))
        {
            Serial.println("Connected to MQTT Broker");
            client.subscribe(topic_receive.c_str());
            Serial.println("Subscribed to topic: " + topic_receive);
        }
        else
        {
            Serial.print("Failed, rc=");
            Serial.print(client.state());
            Serial.println(" Retrying in 5 seconds");
            delay(5000);
        }
    }
}
