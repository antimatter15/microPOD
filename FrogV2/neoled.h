
#include "soc/soc_caps.h"
#include "esp32-hal-rgb-led.h"

void neopixelWrite2(uint8_t pin, uint16_t ledIndex, uint8_t red_val, uint8_t green_val, uint8_t blue_val, uint16_t numLeds) {
#if SOC_RMT_SUPPORTED
  // Calculate the total number of RMT symbols needed
  size_t totalSymbols = numLeds * 24;
  rmt_data_t* led_data = (rmt_data_t*)malloc(totalSymbols * sizeof(rmt_data_t));

  if (led_data == NULL) {
    log_e("Failed to allocate memory for LED data");
    return;
  }

  // Verify if the pin used is RGB_BUILTIN and fix GPIO number
#ifdef RGB_BUILTIN
  pin = pin == RGB_BUILTIN ? pin - SOC_GPIO_PIN_COUNT : pin;
#endif

  if (!rmtInit(pin, RMT_TX_MODE, RMT_MEM_NUM_BLOCKS_1, 10000000)) {
    log_e("RGB LED driver initialization failed for GPIO%d!", pin);
    free(led_data);
    return;
  }

  // Initialize all LEDs to off (0, 0, 0)
  for (uint16_t led = 0; led < numLeds; led++) {
    int colors[3] = {0, 0, 0};
    if (led == ledIndex) {
      colors[0] = green_val;
      colors[1] = red_val;
      colors[2] = blue_val;
    }

    for (int col = 0; col < 3; col++) {
      for (int bit = 0; bit < 8; bit++) {
        size_t i = led * 24 + col * 8 + bit;
        if ((colors[col] & (1 << (7 - bit)))) {
          // HIGH bit
          led_data[i].level0 = 1;     // T1H
          led_data[i].duration0 = 8;  // 0.8us
          led_data[i].level1 = 0;     // T1L
          led_data[i].duration1 = 4;  // 0.4us
        } else {
          // LOW bit
          led_data[i].level0 = 1;     // T0H
          led_data[i].duration0 = 4;  // 0.4us
          led_data[i].level1 = 0;     // T0L
          led_data[i].duration1 = 8;  // 0.8us
        }
      }
    }
  }

  rmtWrite(pin, led_data, totalSymbols, RMT_WAIT_FOR_EVER);
  free(led_data);
#else
  log_e("RMT is not supported on " CONFIG_IDF_TARGET);
#endif /* SOC_RMT_SUPPORTED */
}
