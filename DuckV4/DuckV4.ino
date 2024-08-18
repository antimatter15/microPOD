#include <mbedtls/bignum.h>
#include <esp_bignum.h>
#include "mbedtls/base64.h"
#include <pod_util.h>
#include <blake.h>
#include <ArduinoJson.h>
#include <Preferences.h>


#include <Arduino.h>
#include "esp_sleep.h"
#include "neoled.h"
#include "Wire.h"
#include "driver/ledc.h"
#include <SparkFun_ST25DV64KC_Arduino_Library.h> // Click here to get the library:  http://librarymanager/All#SparkFun_ST25DV64KC

SFE_ST25DV64KC_NDEF tag;

#define VEXT_PIN 0
#define VBAT_PIN 1
#define BEAK_PIN 3
#define SW_PIN 2
#define GPO_PIN 4
#define BUZ_PIN 5
#define VNFC_PIN 10
#define LED_PIN 6
#define SCL_PIN 8
#define SDA_PIN 9
#define LED_EN 7


#define RGB_BRIGHTNESS 16


Preferences preferences;

static volatile bool interruptChanged = false;

void myISR() // Interrupt Service Routine
{
  interruptChanged = true;
}





void goToSleep() {
  pinMode(SW_PIN, OUTPUT);
  digitalWrite(SW_PIN, HIGH);
  delay(5);
  pinMode(SW_PIN, INPUT);

  esp_deep_sleep_enable_gpio_wakeup(1 << VEXT_PIN, ESP_GPIO_WAKEUP_GPIO_HIGH);
  esp_deep_sleep_enable_gpio_wakeup(1 << GPO_PIN, ESP_GPIO_WAKEUP_GPIO_HIGH);
  esp_deep_sleep_enable_gpio_wakeup(1 << SW_PIN, ESP_GPIO_WAKEUP_GPIO_LOW);
  gpio_pulldown_dis(GPIO_NUM_2);
  gpio_pullup_dis(GPIO_NUM_2);
  gpio_hold_en(GPIO_NUM_2);
  esp_deep_sleep_start();
}





void setup() {
  // put your setup code here, to run once:
  Serial.begin(115200);


  preferences.begin("crypto2", false);

  unsigned int start_init_time = millis();
  init_babyjub_constants();
  Serial.print("Init constants time: ");
  Serial.println(millis() - start_init_time);


  pinMode(VEXT_PIN, INPUT);

  pinMode(SDA_PIN, INPUT_PULLUP);
  pinMode(SCL_PIN, INPUT_PULLUP);

  pinMode(SW_PIN, INPUT);
  pinMode(VNFC_PIN, OUTPUT);

  pinMode(VEXT_PIN, OUTPUT);
  pinMode(BUZ_PIN, OUTPUT);


  pinMode(LED_EN, OUTPUT);
  digitalWrite(LED_EN, LOW);
  pinMode(LED_PIN, INPUT);
  pinMode(GPO_PIN, INPUT);
  pinMode(VEXT_PIN, INPUT_PULLDOWN);


  analogReadResolution(8);  // Set ADC resolution to 12 bits
  //  analogSetCycles(255);
  //  analogSetSamples(16);
  analogSetAttenuation(ADC_2_5db);  // Set attenuation for 0-3.3V range

  if (digitalRead(VEXT_PIN)) {

    Serial.println("External power found");

    attachInterrupt(digitalPinToInterrupt(GPO_PIN), myISR, CHANGE);
    attachInterrupt(digitalPinToInterrupt(VEXT_PIN), goToSleep, FALLING);

  } else {
    runChecks();
    goToSleep();
  }



}



void runChecks() {
  checkButton();
  checkNFC();
}



unsigned int lastThing = 0;
void checkNFC() {
  if (lastThing && millis() - lastThing < 5000) {
    return;
  }

  digitalWrite(VNFC_PIN, HIGH);
  delay(50);

  Wire.setPins(SDA_PIN, SCL_PIN); // SDA, SCL
  Wire.begin(); // Start I2C communication

  if (!tag.begin(Wire)) {
    Serial.println("ST25 not detected.");


    pinMode(LED_PIN, OUTPUT);
    digitalWrite(LED_EN, HIGH);
    delay(10);
    for (int i = 0; i < 6; i++) {
      neopixelWrite2(LED_PIN, i, RGB_BRIGHTNESS, 0, 0, 6);
      
      delay(50);
    }
    pinMode(LED_PIN, INPUT);
    digitalWrite(LED_EN, LOW);
  }


  if (tag.RFFieldDetected()) {
    lastThing = millis();
    digitalWrite(VNFC_PIN, LOW);


    ledcAttach(BUZ_PIN, 4100, 8);

    pinMode(LED_PIN, OUTPUT);
    digitalWrite(LED_EN, HIGH);
    delay(10);
    for (int i = 0; i < 6; i++) {
      neopixelWrite2(LED_PIN, i, RGB_BRIGHTNESS, 0, 0, 6);
      ledcWriteNote(BUZ_PIN, (note_t) i, 8);
      delay(200);
    }

    pinMode(LED_PIN, INPUT);
    digitalWrite(LED_EN, LOW);
    ledcDetach(BUZ_PIN);

    delay(100);

    //    while (tag.RFFieldDetected()) {
    //      delay(100);
    //    }
    //    writeNFC();
  }




}


void didReadNFC() {
  ledcAttach(BUZ_PIN, 4100, 8);

  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_EN, HIGH);
  delay(10);
  for (int i = 0; i < 6; i++) {
    neopixelWrite2(LED_PIN, i, RGB_BRIGHTNESS, 0, 0, 6);
    ledcWriteNote(BUZ_PIN, (note_t) i, 8);
    delay(200);
  }

  pinMode(LED_PIN, INPUT);
  digitalWrite(LED_EN, LOW);
  ledcDetach(BUZ_PIN);
}



//
//void checkButton() {
//  if (digitalRead(SW_PIN)) {
//    Serial.println("SW PIN DOWN");
//    pinMode(LED_PIN, OUTPUT);
//    digitalWrite(LED_EN, HIGH);
//    ledcAttach(BUZ_PIN, 4100, 8);
//    ledcWriteNote(BUZ_PIN, NOTE_C, 8);
//
//    //    delay(10);
//    for (int i = 0; i < 6; i++) {
//      neopixelWrite2(LED_PIN, i, 0, 0, RGB_BRIGHTNESS, 6);
//      delay(10);
//    }
//    ledcDetach(BUZ_PIN);
//
//
//    ecdsa_test();
//
//    ledcWriteNote(BUZ_PIN, NOTE_D, 8);
//    for (int i = 0; i < 6; i++) {
//      neopixelWrite2(LED_PIN, i, 0, 0, RGB_BRIGHTNESS, 6);
//      delay(50);
//    }
//    ledcDetach(BUZ_PIN);
//
//
//    pinMode(LED_PIN, INPUT);
//    digitalWrite(LED_EN, LOW);
//  }
//}
//


void checkButton() {
  int value = analogRead(SW_PIN);
  if (value < 250) {
    //    analogRead(SW_PIN);
    //    analogRead(SW_PIN);
    //    analogRead(SW_PIN);
    //    pinMode(SW_PIN, OUTPUT);
    //    digitalWrite(SW_PIN, LOW);
    //    pinMode(SW_PIN, INPUT);

    delay(30);
    int sum = 0;
    for (int i = 0; i < 200; i++) {
      sum += analogRead(SW_PIN);
    }

    if (sum > 50000) return;
    Serial.print("Hi - ");
    Serial.println(value);
    Serial.println(sum);

    //    Serial.println(pinValue);
    pinMode(SW_PIN, INPUT);


    pinMode(LED_PIN, OUTPUT);
    digitalWrite(LED_EN, HIGH);
    ledcAttach(BUZ_PIN, 4100, 8);


    if (sum > 17000 && sum < 22000) {
      ledcWriteNote(BUZ_PIN, NOTE_C, 8);
      for (int i = 0; i < 6; i++) {
        neopixelWrite2(LED_PIN, i, 0, 0, RGB_BRIGHTNESS, 6);
        delay(50);
      }
    } else if (sum > 25000 && sum < 29000) {

//      ledcWriteNote(BUZ_PIN, NOTE_B, 8);
      ecdsa_test();
      for (int i = 0; i < 6; i++) {
        neopixelWrite2(LED_PIN, i, RGB_BRIGHTNESS, RGB_BRIGHTNESS, 0, 6);
        ledcWriteNote(BUZ_PIN, (note_t) i, 8);
        delay(20);
      }


    } else if (sum > 35000 && sum < 39000) {
      ledcWriteNote(BUZ_PIN, NOTE_A, 8);
      for (int i = 0; i < 6; i++) {
        neopixelWrite2(LED_PIN, i, RGB_BRIGHTNESS, 0, 0, 6);
        delay(50);
      }
    }





    ledcDetach(BUZ_PIN);
    pinMode(LED_PIN, INPUT);
    digitalWrite(LED_EN, LOW);
  }
}


int blinkIndex = 0;
unsigned long lastBlink = 0;

void loop() {
  runChecks();

  if (millis() - lastBlink > 100) {
    lastBlink = millis();

    pinMode(LED_PIN, OUTPUT);
    digitalWrite(LED_EN, HIGH);
    blinkIndex++;
    neopixelWrite2(LED_PIN, blinkIndex % 6, 0, RGB_BRIGHTNESS, 0, 6);
  }
}


void ecdsa_test() {

  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_EN, HIGH);
  delay(10);
  neopixelWrite2(LED_PIN, 4, RGB_BRIGHTNESS, RGB_BRIGHTNESS, 0, 6);

  StaticJsonDocument<300> doc;
  unsigned int beginTime = millis();

  int number = preferences.getInt("number", 1);


  doc["counter"]["type"] = "int";
  doc["counter"]["value"] = number;

  doc["zupass_description"]["type"] = "string";
  doc["zupass_description"]["value"] = "#" + String(number) + " Signed by Duck";

  doc["zupass_display"]["type"] = "string";
  doc["zupass_display"]["value"] = "collectable";

  doc["zupass_image_url"]["type"] = "string";
  doc["zupass_image_url"]["value"] = "https://z.kkwok.dev/duck-081624.jpg";

  doc["zupass_title"]["type"] = "string";
  doc["zupass_title"]["value"] = "CyberDuck";


  Serial.println("Building tree...");
  int ledstep = 0;

  
      

      
  int count = doc.size() * 2;
  mbedtls_mpi *items = (mbedtls_mpi*)malloc(sizeof(mbedtls_mpi) * count);
  int index = 0;
  for (JsonPair kv : doc.as<JsonObject>()) {
    const char* key = kv.key().c_str();
    Serial.println(key);

    JsonObject value = kv.value().as<JsonObject>();
    mbedtls_mpi_init(&items[index]);
    mbedtls_mpi_init(&items[index + 1]);
    sha256_hash_mpi(&items[index], key, strlen(key));

    if (strcmp(value["type"], "int") == 0) {
      neopixelWrite2(LED_PIN, (ledstep++) % 6, RGB_BRIGHTNESS, RGB_BRIGHTNESS, 0, 6);
      
      mbedtls_mpi input;
      mbedtls_mpi_init(&input);
      mbedtls_mpi_lset(&input, value["value"].as<int>());
      poseidon(&items[index + 1], &input, 1);
      mbedtls_mpi_free(&input);
    } else if (strcmp(value["type"], "string") == 0) {
      const char* str_value = value["value"];
      sha256_hash_mpi(&items[index + 1], str_value, strlen(str_value));
    }
    index += 2;
  }
  

  
  Serial.print("Computing Merkle Tree... ");
  while (count > 1) {
    for (int i = 0; i < count; i += 2) {
      Serial.print(i);
      if (i + 1 < count) {
        neopixelWrite2(LED_PIN, (ledstep++) % 6, RGB_BRIGHTNESS, RGB_BRIGHTNESS, 0, 6);
        poseidon(&items[i / 2], &items[i], 2);
      } else {
        mbedtls_mpi_copy(&items[i / 2], &items[i]);
      }
    }
    count = (count + 1) / 2;
  }
  Serial.print(" Time (ms): ");
  Serial.println(millis() - beginTime);

  char result_str[200];
  size_t olen;
  mbedtls_mpi_write_string(&items[0], 10, result_str, sizeof(result_str), &olen);
  Serial.print("Poseidon2 Merkle Root: ");
  Serial.println(result_str);

  mbedtls_mpi message;
  mbedtls_mpi_init(&message);
  mbedtls_mpi_copy(&message, &items[0]);
  for (int i = 0; i < doc.size() * 2; i++) mbedtls_mpi_free(&items[i]);
  free(items);

  uint8_t privateKey[32];
  if (preferences.getBytes("privateKey", privateKey, 32) != 32) {
    Serial.println("Generating Private Key");
    esp_fill_random(privateKey, 32);
    preferences.putBytes("privateKey", privateKey, 32);
  }

  char x_str[200], y_str[200];
  neopixelWrite2(LED_PIN, (ledstep++) % 6, RGB_BRIGHTNESS, RGB_BRIGHTNESS, 0, 6);
  
  uint8_t sBuff[64];
  blake512_hash(sBuff, privateKey, 32);

  neopixelWrite2(LED_PIN, (ledstep++) % 6, RGB_BRIGHTNESS, RGB_BRIGHTNESS, 0, 6);

  // pruneBuffer
  sBuff[0] = sBuff[0] & 0xF8;
  sBuff[31] = sBuff[31] & 0x7F;
  sBuff[31] = sBuff[31] | 0x40;

  mbedtls_mpi s;
  mbedtls_mpi_init(&s);
  reverse_endianness(sBuff, 32);
  mbedtls_mpi_read_binary(&s, sBuff, 32);

  // Serial.println("Private Key (s):");
  // mbedtls_mpi_write_string(&s, 10, y_str, sizeof(y_str), &olen);
  // Serial.println(y_str);

  // Process second half of sBuff and message
  uint8_t rBuff[64];
  memset(rBuff, 0, 64);
  memcpy(rBuff, sBuff + 32, 32);
  mbedtls_mpi_write_binary(&message, rBuff + 32, 32);
  reverse_endianness(rBuff + 32, 32); // Ensure little-endian
  blake512_hash(rBuff, rBuff, 64);

  // Calculate r = rBuff % SubOrder
  mbedtls_mpi r;
  mbedtls_mpi_init(&r);
  reverse_endianness(rBuff, 64); // Ensure little-endian
  mbedtls_mpi_read_binary(&r, rBuff, 64);
  mbedtls_mpi_mod_mpi(&r, &r, &SubOrder);

  // Serial.println("r:");
  // mbedtls_mpi_write_string(&r, 10, y_str, sizeof(y_str), &olen);
  // Serial.println(y_str);

  // ss = s >> 3
  mbedtls_mpi ss;
  mbedtls_mpi_init(&ss);
  mbedtls_mpi_copy(&ss, &s);
  mbedtls_mpi_shift_r(&ss, 3);


  // calculate A (public key) = Base8 * ss
  Point A;
  mbedtls_mpi_init(&A.X); mbedtls_mpi_init(&A.Y); mbedtls_mpi_init(&A.Z);

  String pkX = preferences.getString("publicKey.x", "");
  String pkY = preferences.getString("publicKey.y", "");

  if (pkX.isEmpty() || pkY.isEmpty()) {
    Serial.println("Deriving Public Key... ");
    unsigned int startTime = millis();
    neopixelWrite2(LED_PIN, (ledstep++) % 6, RGB_BRIGHTNESS, RGB_BRIGHTNESS, 0, 6);
    multiply_bj(&A, &Base8, &ss);
    mbedtls_mpi_write_string(&A.X, 10, x_str, sizeof(x_str), &olen);
    mbedtls_mpi_write_string(&A.Y, 10, y_str, sizeof(y_str), &olen);
    Serial.println(x_str);
    Serial.println(y_str);

    preferences.putString("publicKey.x", x_str);
    preferences.putString("publicKey.y", y_str);

    Serial.print("Time: ");
    Serial.println(millis() - startTime);
  } else {
    mbedtls_mpi_read_string(&A.X, 10, pkX.c_str());
    mbedtls_mpi_read_string(&A.Y, 10, pkY.c_str());
    mbedtls_mpi_lset(&A.Z, 1);
  }

  uint8_t pubKey[32];
  mbedtls_mpi_write_binary(&A.Y, pubKey, 32);
  reverse_endianness(pubKey, 32); // Ensure little-endian
  if (mbedtls_mpi_cmp_mpi(&A.X, &pm1d2) > 0) pubKey[31] |= 0x80;


  size_t base64_len;
  unsigned char base64_pubkey[45];  // ceil(32 * 4/3) + 1 for null terminator
  mbedtls_base64_encode(base64_pubkey, sizeof(base64_pubkey), &base64_len, pubKey, 32);
  base64_pubkey[base64_len] = '\0';
  Serial.print("Base64 Public Key: ");
  Serial.println((char*)base64_pubkey);

  // Calculate R8
  Point R8;
  mbedtls_mpi_init(&R8.X); mbedtls_mpi_init(&R8.Y); mbedtls_mpi_init(&R8.Z);
  Serial.print("Computing Signature (R8)... ");
  neopixelWrite2(LED_PIN, (ledstep++) % 6, RGB_BRIGHTNESS, RGB_BRIGHTNESS, 0, 6);
  unsigned int startTime = millis();
  multiply_bj(&R8, &Base8, &r);

  mbedtls_mpi_write_string(&R8.X, 10, x_str, sizeof(x_str), &olen);
  mbedtls_mpi_write_string(&R8.Y, 10, y_str, sizeof(y_str), &olen);
  Serial.print(x_str);
  Serial.print(", ");
  Serial.println(y_str);

  Serial.print("Time: ");
  Serial.println(millis() - startTime);



  mbedtls_mpi inputs[5];
  inputs[0] = R8.X;
  inputs[1] = R8.Y;
  inputs[2] = A.X;
  inputs[3] = A.Y;
  inputs[4] = message;

  neopixelWrite2(LED_PIN, (ledstep++) % 6, RGB_BRIGHTNESS, RGB_BRIGHTNESS, 0, 6);
  
  mbedtls_mpi hms;
  mbedtls_mpi_init(&hms);
  Serial.print("Computing Poseidon5 Hash... ");
  startTime = millis();
  poseidon(&hms, inputs, 5);

  mbedtls_mpi_write_string(&hms, 10, x_str, sizeof(x_str), &olen);
  Serial.println(x_str);

  Serial.print("Time: ");
  Serial.println(millis() - startTime);


  // S = (r + hms*s) % SubOrder
  mbedtls_mpi S;
  mbedtls_mpi_init(&S);
  mbedtls_mpi_mul_mpi(&S, &hms, &s);
  mbedtls_mpi_add_mpi(&S, &r, &S);
  mbedtls_mpi_mod_mpi(&S, &S, &SubOrder);

  //  Serial.println("S:");
  //  mbedtls_mpi_write_string(&S, 10, x_str, sizeof(x_str), &olen);
  //  Serial.println(x_str);

  uint8_t signature[64];
  memset(signature, 0, 64);

  mbedtls_mpi_write_binary(&R8.Y, signature, 32);
  reverse_endianness(signature, 32); // Ensure little-endian
  if (mbedtls_mpi_cmp_mpi(&R8.X, &pm1d2) > 0) signature[31] |= 0x80;


  mbedtls_mpi_write_binary(&S, signature + 32, 32);
  reverse_endianness(signature + 32, 32); // Ensure little-endian


  base64_len = 0;
  unsigned char base64_signature[90];  // ceil(32 * 4/3) + 1 for null terminator
  mbedtls_base64_encode(base64_signature, sizeof(base64_signature), &base64_len, signature, 64);
  base64_signature[base64_len] = '\0';
  Serial.print("Base64 EdDSA Signature: ");
  Serial.println((char*)base64_signature);
  neopixelWrite2(LED_PIN, (ledstep++) % 6, RGB_BRIGHTNESS, RGB_BRIGHTNESS, 0, 6);

  preferences.putInt("number", number + 1);

  StaticJsonDocument<1024> pcd;
  String uuid = generateUUID();
  pcd["id"] = uuid;

  JsonObject claim = pcd.createNestedObject("claim");
  claim["entries"] = doc;
  claim["signerPublicKey"] = base64_pubkey;

  JsonObject proof = pcd.createNestedObject("proof");
  proof["signature"] = base64_signature;

  // Pretty print JSON directly to Serial
  //  serializeJsonPretty(pcd, Serial);
  //  Serial.println();

  String jsonPCDString;
  serializeJson(pcd, jsonPCDString);
  

  StaticJsonDocument<1024> addLink;

  addLink["type"] = "Add";
  addLink["redirectToFolder"] = "true";
  addLink["folder"] = "0xPODs";
  addLink["returnUrl"] = "https://zupass.org/";

  JsonObject addLinkPCD = addLink.createNestedObject("pcd");
  addLinkPCD["type"] = "pod-pcd";
  addLinkPCD["pcd"] = jsonPCDString;

  Serial.print("Total Elapsed Time (ms): ");
  Serial.println(millis() - beginTime);

  String addLinkJsonString;
  serializeJson(addLink, addLinkJsonString);
  String zupassURL = "https://zupass.org/#/add?request=" + urlEncode(addLinkJsonString);

  Serial.println();
  Serial.println(zupassURL.c_str());
  neopixelWrite2(LED_PIN, (ledstep++) % 6, RGB_BRIGHTNESS, RGB_BRIGHTNESS, 0, 6);


  String mini = "z.kkwok.dev/?";
  for (JsonPair kv : doc.as<JsonObject>()) {
    const char* key = kv.key().c_str();
    mini += urlEncode(String(key));
    JsonObject value = kv.value().as<JsonObject>();
    if (strcmp(value["type"], "int") == 0) {
      mini += "=" + urlEncode(String(value["value"].as<int>()));
    } else if (strcmp(value["type"], "string") == 0) {
      mini += ":" + urlEncode(String(value["value"]));
    }
    mini += ";";
  }
  mini += String((char*) base64_pubkey);
  mini += ";";
  mini += String((char*) base64_signature);

  Serial.println(mini);


  digitalWrite(VNFC_PIN, HIGH);
  delay(50);
  Wire.setPins(SDA_PIN, SCL_PIN); // SDA, SCL
  Wire.begin(); // Start I2C communication

  if (!tag.begin(Wire)) {
    Serial.println("ST25 not detected.");

    pinMode(LED_PIN, OUTPUT);
    digitalWrite(LED_EN, HIGH);
    delay(10);
    for (int i = 0; i < 6; i++) {
      neopixelWrite2(LED_PIN, i, RGB_BRIGHTNESS, 0, 0, 6);
      
      delay(50);
    }
    pinMode(LED_PIN, INPUT);
    digitalWrite(LED_EN, LOW);

  } else {
    Serial.println("ST25  detected. ");
  }

  tag.setGPO1Bit(BIT_GPO1_FIELD_CHANGE_EN, false);
  tag.setGPO1Bit(BIT_GPO1_RF_USER_EN, false);
  tag.setGPO1Bit(BIT_GPO1_RF_ACTIVITY_EN, false);
  tag.setGPO1Bit(BIT_GPO1_RF_INTERRUPT_EN, false);
  tag.setGPO1Bit(BIT_GPO1_RF_PUT_MSG_EN, false);
  tag.setGPO1Bit(BIT_GPO1_RF_GET_MSG_EN, true);
  tag.setGPO1Bit(BIT_GPO1_RF_WRITE_EN, false);
  tag.setGPO1Bit(BIT_GPO1_GPO_EN, true);

  tag.writeCCFile4Byte();
  tag.writeNDEFURI(mini.c_str(), SFE_ST25DV_NDEF_URI_ID_CODE_HTTPS);
  delay(10);

  pinMode(LED_PIN, INPUT);
  digitalWrite(LED_EN, LOW);



  // Cleanup
  mbedtls_mpi_free(&A.X); mbedtls_mpi_free(&A.Y); mbedtls_mpi_free(&A.Z);
  mbedtls_mpi_free(&R8.X); mbedtls_mpi_free(&R8.Y);mbedtls_mpi_free(&R8.Z);

  mbedtls_mpi_free(&hms);
  mbedtls_mpi_free(&ss);
  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&S);
  mbedtls_mpi_free(&r);
}
