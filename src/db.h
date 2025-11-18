#pragma once
#include <Arduino.h>
#include <Preferences.h>
#include <nvs.h>
#include <nvs_flash.h>
#include <ArduinoJson.h>



void saveData(const String &key, const String &value);
String getData(const String &key);
void removeAll();
JsonDocument listAll();
