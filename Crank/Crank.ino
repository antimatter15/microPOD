#include <Adafruit_GFX.h>
#include <Fonts/FreeMonoBold9pt7b.h>
#include <Fonts/FreeSansBold9pt7b.h>
#include <SPI.h>
#include <SD.h>
#include <Preferences.h>
#include <esp_system.h>
#include "esp_idf_version.h"
#include "eink.h"

#include <mbedtls/bignum.h>
#include "poseidon_constants.h"
#include "esp32c3_bignum.h"
#include "blake.h"
#include "mbedtls/sha256.h"
#include "mbedtls/base64.h"
#include <ArduinoJson.h>
#include "qrcode.h"

const int chipSelect = 9; // Chip select pin for the SD card
const int analogPin1 = A0;
const int analogPin2 = A1;
const int analogPin3 = A3;
Preferences preferences;




GFXcanvas1 gfx = GFXcanvas1(EPD_WIDTH, EPD_HEIGHT);
int itercount = 0;
int counter;
bool connectedSD = false;
String message = "UNABLE TO LOAD";



// Define a struct for representing points
typedef struct {
  mbedtls_mpi x;
  mbedtls_mpi y;
} Point;

// Constants
mbedtls_mpi P, Order, SubOrder, BjA, BjD, pm1d2;
Point Base8;
Modulus Pmod;

mbedtls_mpi FIVE_BIGNUM;
mbedtls_mpi temp1, temp2, temp3, temp4, inv_result;
mbedtls_mpi x1y2, y1x2, x1x2, y1y2, BjDx1x2y1y2;


String generateUUID() {
  const char* hexChars = "0123456789abcdef";
  String uuid = "";

  for (int i = 0; i < 36; i++) {
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      uuid += "-";
    } else if (i == 14) {
      uuid += "4"; // Version 4 UUID
    } else if (i == 19) {
      uuid += hexChars[esp_random() % 4 + 8]; // 8, 9, a, or b for variant
    } else {
      uuid += hexChars[esp_random() % 16];
    }
  }

  return uuid;
}

void sha256_hash_mpi(mbedtls_mpi *result, const char *input, size_t input_len) {
  mbedtls_sha256_context sha256_ctx;
  mbedtls_sha256_init(&sha256_ctx);
  mbedtls_sha256_starts(&sha256_ctx, 0); // 0 for SHA-256
  mbedtls_sha256_update(&sha256_ctx, (const unsigned char *)input, input_len);
  unsigned char key_hash[32];
  mbedtls_sha256_finish(&sha256_ctx, key_hash);
  mbedtls_sha256_free(&sha256_ctx);
  mbedtls_mpi_read_binary(result, key_hash, 32);
  mbedtls_mpi_shift_r(result, 8);
}

void cleanup_constants() {
  
  mbedtls_mpi_free(&FIVE_BIGNUM);
  
  mbedtls_mpi_free(&pm1d2);
  mbedtls_mpi_free(&Base8.x); mbedtls_mpi_free(&Base8.y);
  mbedtls_mpi_free(&P); mbedtls_mpi_free(&Order);
  mbedtls_mpi_free(&SubOrder); mbedtls_mpi_free(&BjA); mbedtls_mpi_free(&BjD);
}


// Initialize constants
void init_constants(void) {
  
  mbedtls_mpi_init(&FIVE_BIGNUM);
  mbedtls_mpi_lset(&FIVE_BIGNUM, 5);
  
  mbedtls_mpi_init(&temp1); mbedtls_mpi_init(&temp2);
  mbedtls_mpi_init(&temp3); mbedtls_mpi_init(&temp4);
  mbedtls_mpi_init(&inv_result);
  mbedtls_mpi_init(&x1y2); mbedtls_mpi_init(&y1x2);
  mbedtls_mpi_init(&x1x2); mbedtls_mpi_init(&y1y2);
  mbedtls_mpi_init(&BjDx1x2y1y2);

  
  mbedtls_mpi_init(&P);
  mbedtls_mpi_init(&Order);
  mbedtls_mpi_init(&SubOrder);
  mbedtls_mpi_init(&BjA);
  mbedtls_mpi_init(&BjD);
  mbedtls_mpi_init(&pm1d2);

  mbedtls_mpi_read_string(&pm1d2, 10, "10944121435919637611123202872628637544274182200208017171849102093287904247808");
  mbedtls_mpi_read_string(&P, 10, "21888242871839275222246405745257275088548364400416034343698204186575808495617");
  mbedtls_mpi_read_string(&Order, 10, "21888242871839275222246405745257275088614511777268538073601725287587578984328");
  mbedtls_mpi_copy(&SubOrder, &Order);
  mbedtls_mpi_shift_r(&SubOrder, 3);
  mbedtls_mpi_lset(&BjA, 168700);
  mbedtls_mpi_lset(&BjD, 168696);

  mbedtls_mpi_init(&Base8.x); mbedtls_mpi_init(&Base8.y);
  mbedtls_mpi_read_string(&Base8.x, 10, "5299619240641551281634865583518297030282874472190772894086521144482721001553");
  mbedtls_mpi_read_string(&Base8.y, 10, "16950150798460657717958625567821834550301663161624707787222815936182638968203");

}


void reverse_endianness(uint8_t* buffer, size_t size) {
  for (size_t i = 0; i < size / 2; i++) {
    uint8_t temp = buffer[i];
    buffer[i] = buffer[size - 1 - i];
    buffer[size - 1 - i] = temp;
  }
}


unsigned int lastToggle;
void toggleLED(){
  if(millis() - lastToggle > 70){
    lastToggle = millis();
    digitalWrite(LED_PIN, !digitalRead(LED_PIN));
  }
}


void drawQRCode(esp_qrcode_handle_t qrcode) {
    int qr_size = esp_qrcode_get_size(qrcode);
    int scale = min(EPD_WIDTH, EPD_HEIGHT) / qr_size;
    int qr_x = (EPD_HEIGHT - (qr_size * scale)) / 2;
    int qr_y = (EPD_WIDTH - (qr_size * scale)) / 2;

    for (int y = 0; y < qr_size; y++) {
        for (int x = 0; x < qr_size; x++) {
            if (esp_qrcode_get_module(qrcode, x, y)) {
                gfx.fillRect(qr_x + x * scale, qr_y + y * scale, scale, scale, 0);
            }
        }
    }
}


void setup() {
  //   REGI2C_WRITE_MASK(I2C_BOD, I2C_BOD_THRESHOLD, BROWNOUT_DET_LVL);
  //brownout_ll_set_threshold(3);

  
    Serial.begin(115200);
    
  pinMode(CS_PIN, OUTPUT);
  pinMode(RST_PIN, OUTPUT);
  pinMode(DC_PIN, OUTPUT);
  pinMode(BUSY_PIN, INPUT);

  pinMode(analogPin3, INPUT);
  pinMode(analogPin2, INPUT);
  pinMode(analogPin1, INPUT);


  pinMode(chipSelect, OUTPUT);

  digitalWrite(chipSelect, HIGH);
  digitalWrite(CS_PIN, LOW);


  pinMode(LED_PIN, OUTPUT);

  pinMode(2, OUTPUT);
  digitalWrite(2, LOW);

  preferences.begin("crank", false);

  long start = millis();

  digitalWrite(LED_PIN, HIGH);


//  delay(100);

//  if (SD.begin(chipSelect, SPI, 80000000)) {
//    connectedSD = true;
//  }

    SPI.beginTransaction(SPISettings(10000000, MSBFIRST, SPI_MODE0));
    SPI.begin ();

  digitalWrite(2, HIGH);

  init_constants();
  esp_mpi_mul_mpi_mod_init(&Pmod, &P);
  

  
  bool sdOpen = true;


  gfx.setRotation(3);
  gfx.setFont(&FreeSansBold9pt7b);
  gfx.setTextColor(BLACK);

  EPD_HW_Init_Fast2();

  gfx.fillScreen(WHITE);
  
  gfx.setTextColor(BLACK);
  gfx.setCursor(10, 30);
  gfx.print("ZK EdDSA POD PCD Zupass");

  
  gfx.setCursor(10, EPD_WIDTH - 20);
  gfx.fillRect(0, EPD_WIDTH - 100, EPD_HEIGHT, 100, 1);
  gfx.print("Computing Merkle Tree...");
  
  EPD_WhiteScreen_ALL_Fast(gfx.getBuffer());

  toggleLED();



  
  StaticJsonDocument<256> doc;
  unsigned int beginTime = millis();

  int number = preferences.getInt("number", 1);
  doc["counter"]["type"] = "int";
  doc["counter"]["value"] = number;
  doc["device"]["type"] = "string";
  doc["device"]["value"] = "ESP32-C3 POD Crank";


  int count = doc.size() * 2;
  mbedtls_mpi *items = (mbedtls_mpi*)malloc(sizeof(mbedtls_mpi) * count);
  int index = 0;
  for (JsonPair kv : doc.as<JsonObject>()) {
    toggleLED();
    const char* key = kv.key().c_str();
    JsonObject value = kv.value().as<JsonObject>();
    mbedtls_mpi_init(&items[index]);
    mbedtls_mpi_init(&items[index + 1]);
    sha256_hash_mpi(&items[index], key, strlen(key));

    if (strcmp(value["type"], "int") == 0) {
      mbedtls_mpi input;
      mbedtls_mpi_init(&input);
      mbedtls_mpi_lset(&input, value["value"].as<int>());
      poseidon_fast(&items[index + 1], &input, 1);
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
      toggleLED();
      if (i + 1 < count) {
        poseidon_fast(&items[i / 2], &items[i], 2);
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
    gfx.setCursor(10, EPD_WIDTH - 20);
    gfx.fillRect(0, EPD_WIDTH - 100, EPD_HEIGHT, 100, 1);
    gfx.print("Generating Private Key...");
    EPD_Dis_PartAll(gfx.getBuffer());
    
    Serial.println("Generating Private Key");
    esp_fill_random(privateKey, 32);
    preferences.putBytes("privateKey", privateKey, 32);
  }

  char x_str[200], y_str[200];

  uint8_t sBuff[64];
  toggleLED();
  blake512_hash(sBuff, privateKey, 32);
  toggleLED();
  
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
  toggleLED();
  blake512_hash(rBuff, rBuff, 64);
  toggleLED();

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
  mbedtls_mpi_init(&A.x); mbedtls_mpi_init(&A.y);

  String pkX = preferences.getString("publicKey.x", "");
  String pkY = preferences.getString("publicKey.y", "");

  if (pkX.isEmpty() || pkY.isEmpty()) {
    gfx.setCursor(10, EPD_WIDTH - 20);
    gfx.fillRect(0, EPD_WIDTH - 100, EPD_HEIGHT, 100, 1);
    gfx.print("Deriving Public Key...");
//    EPD_Dis_PartAll(gfx.getBuffer());
    
    Serial.println("Deriving Public Key... ");
    unsigned int startTime = millis();
    multiply_bj_fast(&A, &Base8, &ss);
    mbedtls_mpi_write_string(&A.x, 10, x_str, sizeof(x_str), &olen);
    mbedtls_mpi_write_string(&A.y, 10, y_str, sizeof(y_str), &olen);
    Serial.println(x_str);
    Serial.println(y_str);

    preferences.putString("publicKey.x", x_str);
    preferences.putString("publicKey.y", y_str);

    Serial.print("Time: ");
    Serial.println(millis() - startTime);
  } else {
    mbedtls_mpi_read_string(&A.x, 10, pkX.c_str());
    mbedtls_mpi_read_string(&A.y, 10, pkY.c_str());
  }

  uint8_t pubKey[32];
  mbedtls_mpi_write_binary(&A.y, pubKey, 32);
  reverse_endianness(pubKey, 32); // Ensure little-endian
  if (mbedtls_mpi_cmp_mpi(&A.x, &pm1d2) > 0) pubKey[31] |= 0x80;


  size_t base64_len;
  unsigned char base64_pubkey[45];  // ceil(32 * 4/3) + 1 for null terminator
  mbedtls_base64_encode(base64_pubkey, sizeof(base64_pubkey), &base64_len, pubKey, 32);
  base64_pubkey[base64_len] = '\0';
  Serial.print("Base64 Public Key: ");
  Serial.println((char*)base64_pubkey);

  // Calculate R8
  Point R8;
  mbedtls_mpi_init(&R8.x); mbedtls_mpi_init(&R8.y);
  Serial.print("Computing Signature (R8)... ");
  
  gfx.setCursor(10, EPD_WIDTH - 20);
  gfx.fillRect(0, EPD_WIDTH - 100, EPD_HEIGHT, 100, 1);
  gfx.print("Multiplying Elliptic Curves...");
//  EPD_Dis_PartAll(gfx.getBuffer());
  
  unsigned int startTime = millis();
  multiply_bj_fast(&R8, &Base8, &r);

  mbedtls_mpi_write_string(&R8.x, 10, x_str, sizeof(x_str), &olen);
  mbedtls_mpi_write_string(&R8.y, 10, y_str, sizeof(y_str), &olen);
  Serial.print(x_str);
  Serial.print(", ");
  Serial.println(y_str);

  Serial.print("Time: ");
  Serial.println(millis() - startTime);


  mbedtls_mpi inputs[5];
  inputs[0] = R8.x;
  inputs[1] = R8.y;
  inputs[2] = A.x;
  inputs[3] = A.y;
  inputs[4] = message;

  mbedtls_mpi hms;
  mbedtls_mpi_init(&hms);
  Serial.print("Computing Poseidon5 Hash... ");

//
//  gfx.setCursor(10, EPD_WIDTH - 20);
//  gfx.fillRect(0, EPD_WIDTH - 100, EPD_HEIGHT, 100, 1);
//  gfx.print("Computing Hash...");
//  EPD_Dis_PartAll(gfx.getBuffer());

  
  startTime = millis();
  toggleLED();
  poseidon_fast(&hms, inputs, 5);
  toggleLED();

  mbedtls_mpi_write_string(&hms, 10, x_str, sizeof(x_str), &olen);
  Serial.println(x_str);

  Serial.print("Time: ");
  Serial.println(millis() - startTime);


  gfx.setCursor(10, EPD_WIDTH - 20);
  gfx.fillRect(0, EPD_WIDTH - 100, EPD_HEIGHT, 100, 1);
  gfx.print("Finalizing...");
  EPD_Dis_PartAll(gfx.getBuffer());

  
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

  mbedtls_mpi_write_binary(&R8.y, signature, 32);
  reverse_endianness(signature, 32); // Ensure little-endian
  if (mbedtls_mpi_cmp_mpi(&R8.x, &pm1d2) > 0) signature[31] |= 0x80;


  mbedtls_mpi_write_binary(&S, signature + 32, 32);
  reverse_endianness(signature + 32, 32); // Ensure little-endian
  toggleLED();

  base64_len = 0;
  unsigned char base64_signature[90];  // ceil(32 * 4/3) + 1 for null terminator
  mbedtls_base64_encode(base64_signature, sizeof(base64_signature), &base64_len, signature, 64);
  base64_signature[base64_len] = '\0';
  Serial.print("Base64 EdDSA Signature: ");
  Serial.println((char*)base64_signature);

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
  toggleLED();
  
  StaticJsonDocument<1024> addLink;
  addLink["type"] = "Add";
  //  addLink["returnUrl"] = "https://zupass.org/#/?folder=Protocol%2520Worlds";
  addLink["returnUrl"] = "https://zupass.org/#/";
  JsonObject addLinkPCD = addLink.createNestedObject("pcd");
  addLinkPCD["type"] = "pod-pcd";
  addLinkPCD["pcd"] = jsonPCDString;

  Serial.print("Total Elapsed Time (ms): ");
  Serial.println(millis() - beginTime);

  
  gfx.setCursor(10, EPD_WIDTH - 20);
  gfx.fillRect(0, EPD_WIDTH - 100, EPD_HEIGHT, 100, 1);
  gfx.print("Time (ms): " + String(millis() - beginTime));

//  
//  gfx.fillRect(0, 0, EPD_HEIGHT, 100, 1);
//  gfx.setCursor(10, 20);
//  gfx.print("Zupass EdDSA POD-PCD");
  
  toggleLED();
  String addLinkJsonString;
  serializeJson(addLink, addLinkJsonString);
  String zupassURL = "https://zupass.org/#/add?request=" + urlEncode(addLinkJsonString);

  
  


  

  gfx.fillRect(0, EPD_WIDTH / 2 - 50, EPD_HEIGHT, 100, 1);
  esp_qrcode_config_t cfg = ESP_QRCODE_CONFIG_DEFAULT();
  cfg.display_func = drawQRCode;
  cfg.max_qrcode_version = 40;  // Adjust as needed
  cfg.qrcode_ecc_level = ESP_QRCODE_ECC_LOW;

  // Generate QR Code
  esp_err_t ret = esp_qrcode_generate(&cfg, zupassURL.c_str());
  if (ret != ESP_OK) {
      Serial.println("Failed to generate QR code");
      return;
  }


  EPD_Dis_PartAll(gfx.getBuffer());
  digitalWrite(LED_PIN, HIGH);
  
  EPD_DeepSleep(); //Enter the sleep mode and please do not delete it, otherwise it will reduce the lifespan of the screen.

}


void loop() {
  // put your main code here, to run repeatedly:


  delay(10);

}





String urlEncode(const String& input) {
  const char *hexChars = "0123456789ABCDEF";
  String output = "";

  for (int i = 0; i < input.length(); i++) {
    char c = input.charAt(i);
    if (isAlphaNumeric(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      output += c;
    } else {
      output += '%';
      output += hexChars[(c >> 4) & 0xF];
      output += hexChars[c & 0xF];
    }
  }

  return output;
}



void poseidon_fast(mbedtls_mpi *result, const mbedtls_mpi *inputs, size_t num_inputs) {
  mbedtls_mpi temp, RR;
  mbedtls_mpi state[MAX_INPUTS + 1], s2[MAX_INPUTS + 1];
  size_t t = num_inputs + 1;
  size_t coff = POSEIDON_C_OFF[t - 2];
  size_t moff = (2 * t * t * t - 3 * t * t + t - 6) / 6;

  mbedtls_mpi_init(&temp);
  mbedtls_mpi_init(&RR);

  for (size_t i = 0; i < t; i++) {
    mbedtls_mpi_init(&state[i]);
    mbedtls_mpi_init(&s2[i]);
  }

  // Initialize state
  mbedtls_mpi_lset(&state[0], 0);
  for (size_t i = 1; i < t; i++) {
    mbedtls_mpi_copy(&state[i], &inputs[i - 1]);
  }

  for (size_t r = 0; r < 8 + N_ROUNDS_P[t - 2]; r++) {
    for (size_t i = 0; i < t; i++) {
      mbedtls_mpi_read_binary(&temp, POSEIDON_C[coff + r * t + i], 32);
      mbedtls_mpi_add_mpi(&state[i], &state[i], &temp);
      mbedtls_mpi_mod_mpi(&state[i], &state[i], &P);

      if (i == 0 || r < 4 || r >= 4 + N_ROUNDS_P[t - 2]) {
        mbedtls_mpi_exp_mod(&state[i], &state[i], &FIVE_BIGNUM, &P, &RR);
      }
    }

    for (size_t i = 0; i < t; i++) {
      mbedtls_mpi_lset(&s2[i], 0);
      for (size_t j = 0; j < t; j++) {
        mbedtls_mpi_read_binary(&temp, POSEIDON_M[moff + t * i + j], 32);
        esp_mpi_mul_mpi_mod_rinv(&temp, &temp, &state[j], &Pmod);
        mbedtls_mpi_add_mpi(&s2[i], &s2[i], &temp);
        mbedtls_mpi_mod_mpi(&s2[i], &s2[i], &P);
      }
    }
    for (size_t i = 0; i < t; i++) {
      mbedtls_mpi_copy(&state[i], &s2[i]);
    }
  }

  mbedtls_mpi_copy(result, &state[0]);
  mbedtls_mpi_mod_mpi(result, result, &P);

  // Free allocated memory
  mbedtls_mpi_free(&temp);
  mbedtls_mpi_free(&RR);
  for (size_t i = 0; i < t; i++) {
    mbedtls_mpi_free(&state[i]);
    mbedtls_mpi_free(&s2[i]);
  }
}





// Scalar multiplication on Baby Jubjub curve (corrected iterative version)
void multiply_bj_fast(Point *result, const Point *pt, const mbedtls_mpi *n) {
  Point R, T;
  mbedtls_mpi_init(&R.x); mbedtls_mpi_init(&R.y);
  mbedtls_mpi_init(&T.x); mbedtls_mpi_init(&T.y);

  // Initialize R as the input point
  mbedtls_mpi_copy(&R.x, &pt->x);
  mbedtls_mpi_copy(&R.y, &pt->y);

  // Initialize T as the point at infinity (0, 1)
  mbedtls_mpi_lset(&T.x, 0);
  mbedtls_mpi_lset(&T.y, 1);

  unsigned int lastCheckpoint = millis();

  // Iterate through each bit of n, from least significant to most
  int bitlen = mbedtls_mpi_bitlen(n);
  for (int i = 0; i < bitlen; i++) {
    // If the current bit of n is 1, add R to T
    if (mbedtls_mpi_get_bit(n, i)) {
      add_bj_fast(&T, &T, &R);
    }
    double_bj_fast(&R, &R);
    toggleLED();

    if(millis() - lastCheckpoint > 700){
//      gfx.setCursor(10, EPD_WIDTH - 20);
      gfx.fillRect(0, EPD_WIDTH / 2 - 50, EPD_HEIGHT, 100, 1);
      gfx.fillRect(10, EPD_WIDTH / 2 - 15, (EPD_HEIGHT - 20) * (i ) / ( bitlen), 30, 0);
      EPD_Dis_PartAll(gfx.getBuffer());
      lastCheckpoint = millis();
    }
  }

  
  gfx.fillRect(10, EPD_WIDTH / 2 - 15, (EPD_HEIGHT - 20), 30, 0);

  
  // Copy the result to the output
  mbedtls_mpi_copy(&result->x, &T.x);
  mbedtls_mpi_copy(&result->y, &T.y);

  // Clean up
  mbedtls_mpi_free(&R.x); mbedtls_mpi_free(&R.y);
  mbedtls_mpi_free(&T.x); mbedtls_mpi_free(&T.y);
}


void add_bj_fast(Point *result, const Point *p1, const Point *p2) {
  // Calculate and store x1y2 and y1x2
  esp_mpi_mul_mpi_mod_rinv(&x1y2, &p1->x, &p2->y, &Pmod);
  esp_mpi_mul_mpi_mod_rinv(&y1x2, &p1->y, &p2->x, &Pmod);

  // Calculate x3 = ((x1y2 + y1x2) % P) * inv((1 + BjD x1 x2 y1 y2) % P, P)
  mbedtls_mpi_add_mpi(&temp3, &x1y2, &y1x2);
  mbedtls_mpi_mod_mpi(&temp3, &temp3, &P);

  // Calculate x1x2 and y1y2
  esp_mpi_mul_mpi_mod_rinv(&x1x2, &p1->x, &p2->x, &Pmod);
  esp_mpi_mul_mpi_mod_rinv(&y1y2, &p1->y, &p2->y, &Pmod);

  // Calculate BjDx1x2y1y2
  esp_mpi_mul_mpi_mod_rinv(&temp1, &x1x2, &y1y2, &Pmod);
  esp_mpi_mul_mpi_mod_rinv(&BjDx1x2y1y2, &temp1, &BjD, &Pmod);

  // Calculate (1 + BjD x1 x2 y1 y2) % P
  mbedtls_mpi_add_int(&temp1, &BjDx1x2y1y2, 1);
  mbedtls_mpi_mod_mpi(&temp1, &temp1, &P);

  mbedtls_mpi_inv_mod(&inv_result, &temp1, &P);
  esp_mpi_mul_mpi_mod_rinv(&result->x, &temp3, &inv_result, &Pmod);

  // Calculate y3 = ((y1y2 - BjAx1x2) % P) * inv((P + 1 - BjDx1x2y1y2) % P, P)
  esp_mpi_mul_mpi_mod_rinv(&temp2, &x1x2, &BjA, &Pmod);
  mbedtls_mpi_sub_mpi(&temp4, &y1y2, &temp2);
  mbedtls_mpi_mod_mpi(&temp4, &temp4, &P);

  // Reuse BjDx1x2y1y2 to calculate (P + 1 - BjDx1x2y1y2) % P
  mbedtls_mpi_sub_mpi(&temp1, &P, &BjDx1x2y1y2);
  mbedtls_mpi_add_int(&temp2, &temp1, 1);
  mbedtls_mpi_mod_mpi(&temp2, &temp2, &P);

  mbedtls_mpi_inv_mod(&inv_result, &temp2, &P);
  esp_mpi_mul_mpi_mod_rinv(&result->y, &temp4, &inv_result, &Pmod);
}

void double_bj_fast(Point *result, const Point *p) {
  // Calculate x^2, y^2, and xy
  esp_mpi_mul_mpi_mod_rinv(&x1x2, &p->x, &p->x, &Pmod);  // x^2
  esp_mpi_mul_mpi_mod_rinv(&y1y2, &p->y, &p->y, &Pmod);  // y^2
  esp_mpi_mul_mpi_mod_rinv(&x1y2, &p->x, &p->y, &Pmod);  // xy

  // Calculate BjDx^2y^2
  esp_mpi_mul_mpi_mod_rinv(&temp1, &x1x2, &y1y2, &Pmod);
  esp_mpi_mul_mpi_mod_rinv(&BjDx1x2y1y2, &temp1, &BjD, &Pmod);

  // Calculate x3 = (2xy % P) * inv((1 + BjDx^2y^2) % P, P)
  mbedtls_mpi_add_mpi(&temp1, &x1y2, &x1y2);  // temp1 = 2xy
  mbedtls_mpi_mod_mpi(&temp1, &temp1, &P);
  mbedtls_mpi_add_int(&temp2, &BjDx1x2y1y2, 1);
  mbedtls_mpi_mod_mpi(&temp2, &temp2, &P);
  mbedtls_mpi_inv_mod(&inv_result, &temp2, &P);
  esp_mpi_mul_mpi_mod_rinv(&result->x, &temp1, &inv_result, &Pmod);

  // Calculate y3 = ((y^2 - BjAx^2) % P) * inv((P + 1 - BjDx^2y^2) % P, P)
  esp_mpi_mul_mpi_mod_rinv(&temp1, &x1x2, &BjA, &Pmod);
  mbedtls_mpi_sub_mpi(&temp2, &y1y2, &temp1);
  mbedtls_mpi_mod_mpi(&temp2, &temp2, &P);
  mbedtls_mpi_sub_mpi(&temp3, &P, &BjDx1x2y1y2);
  mbedtls_mpi_add_int(&temp4, &temp3, 1);
  mbedtls_mpi_mod_mpi(&temp4, &temp4, &P);
  mbedtls_mpi_inv_mod(&inv_result, &temp4, &P);
  esp_mpi_mul_mpi_mod_rinv(&result->y, &temp2, &inv_result, &Pmod);
}
