#include "db.h"
Preferences prefs;
void saveData(const String &key, const String &value)
{
    if (key.length() > 32)
    {
        Serial.println("❌ Key 太長（超過 32 字）");
        return;
    }
    if (value.length() > 256)
    {
        Serial.println("❌ Value 太長（超過 256 字）");
        return;
    }
    prefs.begin("kvstore", false);
    prefs.putString(key.c_str(), value);
    prefs.end();
    Serial.printf("✅ 已儲存: [%s] = %s\n", key.c_str(), value.c_str());
}

String getData(const String &key)
{
    prefs.begin("kvstore", true);
    String value = prefs.getString(key.c_str(), "");
    prefs.end();
    if (value.isEmpty())
        Serial.printf("⚠️ 無資料: [%s]\n", key.c_str());
    else
        Serial.printf("📦 讀取: [%s] = %s\n", key.c_str(), value.c_str());
    return value;
}

void removeAll()
{
    prefs.begin("kvstore", false);
    prefs.clear();
    prefs.end();
    Serial.println("🧹 所有資料已刪除");
}


// 列出所有 key/value
JsonDocument listAll()
{
    JsonDocument doc;
    nvs_iterator_t it = nvs_entry_find("nvs", "kvstore", NVS_TYPE_ANY);
    if (it == nullptr)
    {
        Serial.println("⚠️ 沒有任何資料");
        return doc;
    }

    Serial.println("📜 目前儲存內容：");
    while (it != nullptr)
    {
        nvs_entry_info_t info;
        nvs_entry_info(it, &info);
        it = nvs_entry_next(it);

        prefs.begin("kvstore", true);
        String val = prefs.getString(info.key, "");
        prefs.end();

        doc[info.key] = val;
        Serial.printf("  [%s] = %s\n", info.key, val.c_str());
    }
    nvs_release_iterator(it);
    return doc;
}

void processInput(String line)
{
    line.trim();
    if (line.length() == 0)
        return;

    if (line == "remove")
    {
        removeAll();
        return;
    }
    if (line == "list")
    {
        listAll();
        return;
    }

    int spaceIndex = line.indexOf(' ');
    if (spaceIndex == -1)
    {
        // 只輸入 key → 查詢
        getData(line);
    }
    else
    {
        // 有 key + value
        String key = line.substring(0, spaceIndex);
        String value = line.substring(spaceIndex + 1);
        if (value.length() == 0)
        {
            Serial.println("❌ 請輸入要儲存的值");
            return;
        }
        saveData(key, value);
    }
}