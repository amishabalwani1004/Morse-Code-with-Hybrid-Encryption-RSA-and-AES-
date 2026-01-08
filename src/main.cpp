#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include "FS.h"
#include "SPIFFS.h"
#include "mbedtls/gcm.h"

bool sessionKeyReady = false;
unsigned char sessionKey[32];  // AES-256 key

extern "C" {
  #include "mbedtls/pk.h"
  #include "mbedtls/ctr_drbg.h"
  #include "mbedtls/entropy.h"
  #include "mbedtls/base64.h"
}

// ---------- Wi-Fi ----------
const char* ssid     = "YOUR_WIFI_SSID";
const char* password = "YOUR_WIFI_PASSWORD";

// ---------- Pins ----------
#define BUZZER_PIN     4
#define RED_LED_PIN   19
#define GREEN_LED_PIN 23
#define BUTTON_PIN    21

// ---------- Morse Timing ----------
unsigned long pressStart = 0;
unsigned long lastReleaseTime = 0;
bool isPressed = false;
int threshold = 300;
int debounceDelay = 50;
String currentMorse = "";

// ---------- UDP / RSA ----------
WiFiUDP udp;
const uint16_t UDP_PORT = 5005;
char udpBuffer[512];

mbedtls_pk_context pk;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
bool cryptoReady = false;

// ---------- Morse functions ----------
void dot() {
  digitalWrite(RED_LED_PIN, HIGH);
  digitalWrite(BUZZER_PIN, HIGH);
  currentMorse += ".";
  delay(120);
  digitalWrite(RED_LED_PIN, LOW);
  digitalWrite(BUZZER_PIN, LOW);
  delay(120);
}

void dash() {
  digitalWrite(GREEN_LED_PIN, HIGH);
  digitalWrite(BUZZER_PIN, HIGH);
  currentMorse += "-";
  delay(350);
  digitalWrite(GREEN_LED_PIN, LOW);
  digitalWrite(BUZZER_PIN, LOW);
  delay(120);
}

char morseTochar(String code) {
  if (code == ".-") return 'A';
  if (code == "-...") return 'B';
  if (code == "-.-.") return 'C';
  if (code == "-..") return 'D';
  if (code == ".") return 'E';
  if (code == "..-.") return 'F';
  if (code == "--.") return 'G';
  if (code == "....") return 'H';
  if (code == "..") return 'I';
  if (code == ".---") return 'J';
  if (code == "-.-") return 'K';
  if (code == ".-..") return 'L';
  if (code == "--") return 'M';
  if (code == "-.") return 'N';
  if (code == "---") return 'O';
  if (code == ".--.") return 'P';
  if (code == "--.-") return 'Q';
  if (code == ".-.") return 'R';
  if (code == "...") return 'S';
  if (code == "-") return 'T';
  if (code == "..-") return 'U';
  if (code == "...-") return 'V';
  if (code == ".--") return 'W';
  if (code == "-..-") return 'X';
  if (code == "-.--") return 'Y';
  if (code == "--..") return 'Z';
  if (code == "-----") return '0';
  if (code == ".----") return '1';
  if (code == "..---") return '2';
  if (code == "...--") return '3';
  if (code == "....-") return '4';
  if (code == ".....") return '5';
  if (code == "-....") return '6';
  if (code == "--...") return '7';
  if (code == "---..") return '8';
  if (code == "----.") return '9';
  return '?';
}

// ---------- Crypto init ----------
bool initCryptoFromSPIFFS() {
  if (!SPIFFS.begin(true)) {
    Serial.println("[SPIFFS] Mount failed");
    return false;
  }

  File keyFile = SPIFFS.open("/esp32_private.pem", "r");
  if (!keyFile) {
    Serial.println("[SPIFFS] Private key missing!");
    return false;
  }

  String keyStr = keyFile.readString();
  keyFile.close();

  mbedtls_pk_init(&pk);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  const char* pers = "esp32_rsa";
  int ret = mbedtls_ctr_drbg_seed(
    &ctr_drbg,
    mbedtls_entropy_func,
    &entropy,
    (const unsigned char*)pers,
    strlen(pers)
  );
  if (ret != 0) return false;

  ret = mbedtls_pk_parse_key(
    &pk,
    (const unsigned char*)keyStr.c_str(),
    keyStr.length() + 1,
    NULL,
    0
  );

  if (ret != 0) {
    Serial.println("[Crypto] Parse key failed!");
    return false;
  }

  Serial.println("[Crypto] Private key loaded.");
  return true;
}

// ---------- RSA decrypt ----------
String rsaDecryptBase64(const char* b64, size_t b64Len) {
  if (!cryptoReady) return "";

  unsigned char cipher[512];
  size_t cipherLen = 0;
  int ret = mbedtls_base64_decode(cipher, sizeof(cipher), &cipherLen,
                                  (const unsigned char*)b64, b64Len);
  if (ret != 0) return "";

  unsigned char decrypted[512];
  size_t olen = 0;

  ret = mbedtls_pk_decrypt(
    &pk,
    cipher,
    cipherLen,
    decrypted,
    &olen,
    sizeof(decrypted),
    mbedtls_ctr_drbg_random,
    &ctr_drbg
  );
  if (ret != 0) {
    Serial.println("[Crypto] Decrypt failed.");
    return "";
  }

  decrypted[olen] = '\0';
  return String((char*)decrypted);
}

String aesDecryptGCM(const unsigned char *iv, size_t ivLen,
                     const unsigned char *tag,
                     const unsigned char *cipher, size_t cipherLen) {
    
    if (!sessionKeyReady) {
        Serial.println("[AES] No session key set.");
        return "";
    }

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES,
                                 sessionKey, 256); // 256-bit key
    if (ret != 0) {
        Serial.print("[AES] Failed setkey: "); Serial.println(ret);
        mbedtls_gcm_free(&gcm);
        return "";
    }

    unsigned char output[512];
    ret = mbedtls_gcm_auth_decrypt(
        &gcm,
        cipherLen,
        iv, ivLen,
        NULL, 0,          // AAD = none for now
        tag, 16,
        cipher,
        output
    );

    mbedtls_gcm_free(&gcm);

    if (ret != 0) {
        Serial.print("[AES] Auth decrypt failed: "); Serial.println(ret);
        return "";
    }

    output[cipherLen] = '\0';
    return String((char*)output);
}


void handleUdp() {
    int size = udp.parsePacket();
    if (size <= 0) return;

    if (size >= sizeof(udpBuffer)) size = sizeof(udpBuffer) - 1;

    int len = udp.read(udpBuffer, size);
    udpBuffer[len] = '\0';

    String pkt = String(udpBuffer);

    // ----------------------------
    // 1) KEY PACKET (RSA encrypted PSK)
    // ----------------------------
    if (pkt.startsWith("KEY:")) {
        String b64 = pkt.substring(4);
        Serial.println("[UDP] Received KEY packet");

        // base64 decode
        unsigned char cipher[512];
        size_t cipherLen = 0;

        int ret = mbedtls_base64_decode(cipher, sizeof(cipher),
                                        &cipherLen,
                                        (unsigned char*)b64.c_str(),
                                        b64.length());
        if (ret != 0) {
            Serial.println("[KEY] Base64 decode failed");
            return;
        }

        // RSA decrypt
        String psk = rsaDecryptBase64(b64.c_str(), b64.length());
        if (psk.length() != 32) {
            Serial.println("[KEY] RSA decrypted PSK wrong length!");
            return;
        }

        memcpy(sessionKey, psk.c_str(), 32);
        sessionKeyReady = true;

        Serial.println("[KEY] Session AES key installed.");
        return;
    }

    // ----------------------------
    // 2) MSG PACKET (AES-GCM data)
    // ----------------------------
    if (pkt.startsWith("MSG:")) {
        if (!sessionKeyReady) {
            Serial.println("[MSG] No session key yet");
            return;
        }

        Serial.println("[UDP] Received MSG packet");

        // split into iv, tag, cipher
        int p1 = pkt.indexOf(":", 4);
        int p2 = pkt.indexOf(":", p1 + 1);

        if (p1 < 0 || p2 < 0) {
            Serial.println("[MSG] Packet format error");
            return;
        }

        String b64_iv = pkt.substring(4, p1);
        String b64_tag = pkt.substring(p1 + 1, p2);
        String b64_ct = pkt.substring(p2 + 1);

        unsigned char iv[64], tag[64], cipher[512];
        size_t ivLen, tagLen, cipherLen;

        mbedtls_base64_decode(iv, sizeof(iv), &ivLen,
                              (unsigned char*)b64_iv.c_str(), b64_iv.length());
        mbedtls_base64_decode(tag, sizeof(tag), &tagLen,
                              (unsigned char*)b64_tag.c_str(), b64_tag.length());
        mbedtls_base64_decode(cipher, sizeof(cipher), &cipherLen,
                              (unsigned char*)b64_ct.c_str(), b64_ct.length());

        // AES decrypt
        String plaintext = aesDecryptGCM(iv, ivLen, tag, cipher, cipherLen);
        if (plaintext == "") {
            Serial.println("[MSG] AES decrypt failed");
            return;
        }

        Serial.print("[MSG] Decrypted Morse: ");
        Serial.println(plaintext);
        return;
    }

    // fallback
    Serial.println("[UDP] Unknown packet");
}

// ---------- setup ----------
void setup() {
  Serial.begin(115200);

  pinMode(BUZZER_PIN, OUTPUT);
  pinMode(RED_LED_PIN, OUTPUT);
  pinMode(GREEN_LED_PIN, OUTPUT);
  pinMode(BUTTON_PIN, INPUT_PULLUP);

  // WiFi
  Serial.println("Connecting to WiFi...");
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(300);
    Serial.print(".");
  }
  Serial.print("\nConnected! IP = ");
  Serial.println(WiFi.localIP());

  // Crypto
  cryptoReady = initCryptoFromSPIFFS();

  udp.begin(UDP_PORT);
  Serial.printf("UDP listening on port %u\n", UDP_PORT);
}

// ---------- loop ----------
void loop() {
  // Morse input (button)
  static int lastStable = HIGH;
  static int lastRead = HIGH;
  static unsigned long lastDebounce = 0;

  int reading = digitalRead(BUTTON_PIN);
  if (reading != lastRead) lastDebounce = millis();

  if (millis() - lastDebounce > debounceDelay) {
    if (reading != lastStable) {
      lastStable = reading;

      if (lastStable == LOW) {
        pressStart = millis();
        isPressed = true;
      }
      else if (isPressed) {
        unsigned long duration = millis() - pressStart;
        if (duration < threshold) dot();
        else dash();
        isPressed = false;
        lastReleaseTime = millis();
      }
    }
  }

  lastRead = reading;

  if (!isPressed && currentMorse.length() > 0 &&
      (millis() - lastReleaseTime > 700)) {
    char ch = morseTochar(currentMorse);
    Serial.print("Decoded: ");
    Serial.println(ch);
    currentMorse = "";
  }

  handleUdp();
  delay(5);
}
