#include <WiFi.h>
#include <PubSubClient.h>
#include <WebServer.h>
#include "conf.h"

const char* mqtt_server = "test.mosquitto.org";
const int mqtt_port = 1883;
const char* mqtt_topic = "esp32/test-jnsadk23uhe88h87h34r3fiu";

WiFiClient espClient;
PubSubClient client(espClient);
WebServer server(80);

String latestMessage = "尚未收到資料";
unsigned long lastReconnectAttempt = 0;

// HTML + AJAX
const char MAIN_page[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>ESP32 MQTT Web Demo</title>
  <script>
    function fetchData() {
      fetch('/data')
        .then(response => response.text())
        .then(data => {
          document.getElementById("msg").innerHTML = data;
        });
    }
    setInterval(fetchData, 2000);
  </script>
</head>
<body>
  <h2>MQTT 訊息顯示</h2>
  <p>最新訊息：<span id="msg">載入中...</span></p>
</body>
</html>
)rawliteral";

void handleRoot() {
  server.send(200, "text/html", MAIN_page);
}

void handleData() {
  server.send(200, "text/plain", latestMessage);
}

void callback(char* topic, byte* payload, unsigned int length) {
  String message;
  for (unsigned int i = 0; i < length; i++) {
    message += (char)payload[i];
  }
  Serial.printf("收到 MQTT [%s]: %s\n", topic, message.c_str());
  latestMessage = message;
}

bool mqttReconnect() {
      // 使用晶片 ID 生成唯一 Client ID
  String clientId = "ESP32Client-" + String((uint32_t)ESP.getEfuseMac(), HEX);
  if (client.connect(clientId.c_str())) {
    Serial.println("MQTT 已連線");
    client.subscribe(mqtt_topic);
    return true;
  }
  Serial.print("MQTT 連線失敗, rc=");
  Serial.print(client.state());
  Serial.println(" 5 秒後重試");
  return false;
}

void setup() {
  Serial.begin(115200);

  WiFi.begin(ssid, password);
  Serial.print("連線中");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWiFi 連線成功!");
  Serial.print("IP 地址: ");
  Serial.println(WiFi.localIP());

  client.setServer(mqtt_server, mqtt_port);
  client.setCallback(callback);

  server.on("/", handleRoot);
  server.on("/data", handleData);
  server.begin();
}

void loop() {
  server.handleClient();

  if (!client.connected()) {
    unsigned long now = millis();
    if (now - lastReconnectAttempt > 5000) { // 5 秒重試一次
      lastReconnectAttempt = now;
      if (mqttReconnect()) {
        lastReconnectAttempt = 0;
      }
    }
  } else {
    client.loop();
  }
}
