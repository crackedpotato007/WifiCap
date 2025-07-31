// TODO: Figure out telegram upload
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "secrets.h"
#include <stdbool.h>

static const char *TAG = "TELEGRAM";
void stop_sniffer_and_connect(const char *ssid, const char *password) {
  ESP_LOGI(TAG, "Stopping promiscuous mode...");
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous(false)); // Disable sniffer
  ESP_ERROR_CHECK(esp_wifi_stop());

  ESP_LOGI(TAG, "Setting Wi-Fi to STA mode...");
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));

  wifi_config_t wifi_config = {0};
  strncpy((char *)wifi_config.sta.ssid, ssid, sizeof(wifi_config.sta.ssid));
  strncpy((char *)wifi_config.sta.password, password,
          sizeof(wifi_config.sta.password));

  ESP_LOGI(TAG, "Connecting to SSID: %s", ssid);
  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
  ESP_ERROR_CHECK(esp_wifi_start());
  ESP_ERROR_CHECK(esp_wifi_connect());

  // Ensure DHCP is running
  esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
  if (!netif) {
    ESP_LOGE(TAG, "Failed to get netif for WIFI_STA_DEF");
    return;
  }
  ESP_ERROR_CHECK(esp_netif_dhcpc_start(netif));

  esp_netif_ip_info_t ip_info;
  bool got_ip = false;

  for (int i = 0; i < 60; i++) { // 15s max
    if (esp_netif_get_ip_info(netif, &ip_info) == ESP_OK &&
        ip_info.ip.addr != 0) {
      ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&ip_info.ip));
      got_ip = true;
      break;
    }
    vTaskDelay(pdMS_TO_TICKS(500));
  }

  if (!got_ip) {
    ESP_LOGE(TAG, "Failed to get IP after 15s");
  }
}

void send_file_to_telegram(const char *file_path) {
  // Connect to Wi-Fi (your existing function)
  stop_sniffer_and_connect("OnePlus Nord CE4 4C5E", "wmwg5556");

  ESP_LOGI(TAG, "Sending file to Telegram: %s", file_path);
  if (!file_path || strlen(file_path) == 0) {
    ESP_LOGE(TAG, "Invalid file path");
    return;
  }

  // Open file
  FILE *file = fopen(file_path, "rb");
  if (!file) {
    ESP_LOGE(TAG, "Failed to open file: %s", file_path);
    return;
  }

  // Get file size
  fseek(file, 0, SEEK_END);
  long file_size = ftell(file);
  fseek(file, 0, SEEK_SET);
  const char *filename = strrchr(file_path, '/');
  if (filename) {
    filename++; // skip the slash
  } else {
    filename = file_path; // no slash found, use full path
  }
  ESP_LOGI(TAG, "File size: %ld bytes, filename: %s", file_size, filename);
  // Prepare multipart boundaries
  const char *boundary = "----ESP32Boundary";
  char start_part[512];
  snprintf(
      start_part, sizeof(start_part),
      "--%s\r\n"
      "Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n"
      "%s\r\n"
      "--%s\r\n"
      "Content-Disposition: form-data; name=\"document\"; filename=\"%s\"\r\n"
      "Content-Type: application/octet-stream\r\n\r\n",
      boundary, TELEGRAM_CHAT_ID, boundary, filename);

  char end_part[64];
  snprintf(end_part, sizeof(end_part), "\r\n--%s--\r\n", boundary);

  // Calculate total content length
  size_t content_length = strlen(start_part) + file_size + strlen(end_part);

  // Build Telegram API URL
  char url[256];
  snprintf(url, sizeof(url), "https://api.telegram.org/bot%s/sendDocument",
           TELEGRAM_BOT_TOKEN);

  // Configure HTTP client
  esp_http_client_config_t config = {.url = url,
                                     .transport_type = HTTP_TRANSPORT_OVER_SSL,
                                     .crt_bundle_attach = esp_crt_bundle_attach,
                                     .timeout_ms = 30000};

  esp_http_client_handle_t client = esp_http_client_init(&config);

  // Set headers
  char content_type[128];
  snprintf(content_type, sizeof(content_type),
           "multipart/form-data; boundary=%s", boundary);
  esp_http_client_set_header(client, "Content-Type", content_type);

  // Open connection with content length
  esp_err_t err = esp_http_client_open(client, content_length);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open HTTP connection: %s", esp_err_to_name(err));
    fclose(file);
    esp_http_client_cleanup(client);
    return;
  }

  // Send multipart header
  esp_http_client_write(client, start_part, strlen(start_part));

  // Send file data
  char buf[1024];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), file)) > 0) {
    esp_http_client_write(client, buf, n);
  }
  fclose(file);

  // Send multipart footer
  esp_http_client_write(client, end_part, strlen(end_part));

  // Perform the request
  esp_http_client_fetch_headers(client);
  int status = esp_http_client_get_status_code(client);
  ESP_LOGI(TAG, "Telegram HTTP Status: %d", status);

  // Read response
  char resp[512];
  int read_len = esp_http_client_read(client, resp, sizeof(resp) - 1);
  if (read_len > 0) {
    resp[read_len] = '\0';
    ESP_LOGI(TAG, "Telegram response: %s", resp);
  } else {
    ESP_LOGE(TAG, "No response or error reading response");
  }
  esp_http_client_cleanup(client);
  esp_wifi_disconnect();
  ESP_LOGI(TAG, "File sent to Telegram successfully");
  ESP_ERROR_CHECK(esp_wifi_stop());
  if (remove(file_path) == 0) {
    ESP_LOGI(TAG, "File deleted successfully");
  } else {
    ESP_LOGE(TAG, "Failed to delete file");
  }
}