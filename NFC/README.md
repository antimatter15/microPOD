# ESP32-S3 + PN532

This was tested with an [ESP32-S3 Super Mini](https://www.aliexpress.us/item/3256806272305175.html) with a [PN532 module](https://www.aliexpress.us/item/3256804763785321.html). 

## Wiring

- GND on PN532 to GND on ESP32-S3
- VCC on PN532 to 5V on ESP32-S3
- SDA/TXD on PN532 to GPIO 13 on ESP32-S3
- SCL/RXD on PN532 to GPIO 12 on ESP32-S3

The switches are configured to the default position of (0, 0) to represent High-Speed UART (HSU) mode. 

## Software

With the Arduino IDE, install the ESP32 board type, and the ArduinoJson library. 

Select "ESP32-S3 Dev" as a output type. Make sure to enable "CDC On Boot" in order to see serial console output. 

You may need to hold down the "BOOT" button and press the "RESET" button in order to program it. 