#include "base64.h"
#include "display.h"
#include "esp_log.h"
#include "esp_spiffs.h"
#include "esp_system.h" // for esp_get_free_heap_size()
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "libwifi.h"
#include "telegram.h"
#include <ctype.h>
#include <inttypes.h>
#include <string.h>
#include <sys/time.h>

struct pcap_hdr_s {
  uint32_t magic_number;  // 0xa1b2c3d4
  uint16_t version_major; // 2
  uint16_t version_minor; // 4
  int32_t thiszone;       // GMT offset
  uint32_t sigfigs;       // accuracy
  uint32_t snaplen;       // max length of captured packets
  uint32_t network;       // data link type (1 = Ethernet, 105 = IEEE 802.11)
};
struct pcaprec_hdr_s {
  uint32_t ts_sec;   // timestamp seconds
  uint32_t ts_usec;  // timestamp microseconds
  uint32_t incl_len; // number of octets saved in file
  uint32_t orig_len; // original length of packet
};

bool writer_enabled = false;
bool M1 =
    false; // M1 is used to indicate if the first packet is being processed
bool M2 = false; // M2 is used to indicate if the second packet is being
bool M3 =
    false; // M3 is used to indicate if the third packet is being processed
bool M4 =
    false; // M4 is used to indicate if the fourth packet is being processed
FILE *pcap_file = NULL;
bool displayed = false; // Used to ensure we only display once

void write_pcap_header(FILE *f) {
  displayed = false;
  struct pcap_hdr_s hdr;
  hdr.magic_number = 0xa1b2c3d4;
  hdr.version_major = 2;
  hdr.version_minor = 4;
  hdr.thiszone = 0;
  hdr.sigfigs = 0;
  hdr.snaplen = 65535;
  hdr.network = 105; // DLT_IEEE802_11 for Wi-Fi frames

  fwrite(&hdr, sizeof(hdr), 1, f);
}
void sanitize_ssid(const char *input, char *output, size_t max_len) {
  size_t j = 0;
  int in_trim = 0;

  // Skip leading spaces
  while (*input && isspace((unsigned char)*input)) {
    input++;
  }

  // Process characters
  while (*input && j < max_len - 1) {
    if (!isspace((unsigned char)*input)) {
      output[j++] = *input;
      in_trim = 1; // Found a non-space char
    }
    input++;
  }

  // Remove trailing spaces (if any got copied)
  while (j > 0 && isspace((unsigned char)output[j - 1])) {
    j--;
  }

  output[j] = '\0';
}
#define MAX_SSID_LEN 12
#define MAX_FILENAME_LEN 32
char file_path[MAX_FILENAME_LEN];
void start_pcap_writer(char *ssid) {
  displayed = false; // Reset displayed flag
  // file format: /spiffs/capture-ssid.pcap
  char clean_ssid[MAX_SSID_LEN];
  sanitize_ssid(ssid, clean_ssid, sizeof(clean_ssid));

  int written =
      snprintf(file_path, sizeof(file_path), "/spiffs/cap_%s.pcap", clean_ssid);

  if (written >= sizeof(file_path)) {
    ESP_LOGW("PCAP", "Filename truncated to fit buffer");
  }

  ESP_LOGI("PCAP", "Opening file for writing: %s", file_path);
  pcap_file = fopen(file_path, "wb");
  if (!pcap_file) {
    ESP_LOGE("PCAP", "Failed to open file for writing");
    return;
  }
  write_pcap_header(pcap_file);
  writer_enabled = true;
  ESP_LOGI("PCAP", "PCAP file created with header");
}

void close_pcap_writer(void) {
  ESP_LOGI("DEBUG", "writer_enabled: %d, pcap_file: %p", writer_enabled,
           (void *)pcap_file);
  if (!writer_enabled) {
    ESP_LOGE("PCAP", "Writer not enabled but close called!");
    return;
  }
  ESP_LOGD("HEAP", "Free heap: %" PRIu32 " bytes", esp_get_free_heap_size());

  writer_enabled = false;
  vTaskDelay(pdMS_TO_TICKS(200));
  if (pcap_file) {
    fclose(pcap_file);
    pcap_file = NULL;
    ESP_LOGI("PCAP", "PCAP file closed");
  }

  send_file_to_telegram(file_path);
}

void write_pcap_packet(const uint8_t *data, uint32_t len) {
  if (!pcap_file)
    return;
  struct libwifi_frame frame = {0};

  bool wpa_data_initialized = false;
  int ret = libwifi_get_wifi_frame(&frame, (uint8_t *)data, len, false);
  if (ret < 0) {
    ESP_LOGE("PCAP", "Failed to parse Wi-Fi frame: %d", ret);
    return;
  }
  if (libwifi_check_wpa_handshake(&frame) == true) {

    if (libwifi_check_wpa_message(&frame) == HANDSHAKE_M1) {
      M1 = true;
    }
    if (libwifi_check_wpa_message(&frame) == HANDSHAKE_M2) {
      M2 = true;
    }
    if (libwifi_check_wpa_message(&frame) == HANDSHAKE_M3) {
      M3 = true;
    }
    if (libwifi_check_wpa_message(&frame) == HANDSHAKE_M4) {
      M4 = true;
    }
  }

  if (M1 && M2 && M3 && M4 && !displayed) {
    ESP_LOGI("PCAP", "All EAPOL messages received.");
    display("EAPOL handshake capture complete.");
    displayed = true
  }

  struct pcaprec_hdr_s rec;
  struct timeval tv;
  gettimeofday(&tv, NULL);

  rec.ts_sec = tv.tv_sec;
  rec.ts_usec = tv.tv_usec;
  rec.incl_len = len;
  rec.orig_len = len;

  fwrite(&rec, sizeof(rec), 1, pcap_file);
  fwrite(data, len, 1, pcap_file);
  fflush(pcap_file);
  /* Cleanup allocated resources */
  libwifi_free_wifi_frame(&frame);
}

bool is_writer_enabled() { return writer_enabled; }

FILE *get_pcap_file() { return pcap_file; }
TaskHandle_t close_task_handle = NULL;

void close_task(void *arg) {
  for (;;) {
    ulTaskNotifyTake(pdTRUE, portMAX_DELAY); // Wait for notification
    close_pcap_writer();                     // Safe now
  }
}
