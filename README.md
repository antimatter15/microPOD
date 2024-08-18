# microPOD

Minimal Microcontroller implementations of the Programmable Object Data (POD) format. 

## Getting Started

This has only been tested on ESP32C3 and ESP32S3, however the code should be fairly portable.

Install `Arduino ESP32` from Boards Manager

Install `ArduinoJson`


## Notes

See `esp_bignum.h` which roughly contains inlined versions of [ESP-IDF's bignum.c](https://github.com/espressif/esp-idf/blob/release/v5.1/components/mbedtls/port/esp32c3/bignum.c) for ESP32C3, ESP32S2, ESP32S3, and ESP32C6 boards. It also includes non-standard `esp_mpi_mul_mpi_mod_init` and `esp_mpi_mul_mpi_mod_rinv` methods. 

The latest version of the code is in `DuckV4` which uses a montgomery ladder to accelerate EdDSA signatures on the BabyJub curve with code mostly written by Claude and derived from this [MbedTLS pull request](https://github.com/Mbed-TLS/mbedtls/pull/5819) for adding Curve25519 EdDSA. 