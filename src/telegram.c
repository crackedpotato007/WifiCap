//TODO: Figure out telegram upload
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "secrets.h"
#include "esp_crt_bundle.h"

static const char *TAG = "TELEGRAM";
void stop_sniffer_and_connect(const char *ssid, const char *password) {
    ESP_LOGI(TAG, "Stopping promiscuous mode...");
    esp_wifi_set_promiscuous(false);  // Disable sniffer
    ESP_ERROR_CHECK(esp_wifi_stop());

    ESP_LOGI(TAG, "Setting Wi-Fi to STA mode...");
    esp_netif_create_default_wifi_sta();
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));

    wifi_config_t wifi_config = {0};
    strncpy((char *)wifi_config.sta.ssid, ssid, sizeof(wifi_config.sta.ssid));
    strncpy((char *)wifi_config.sta.password, password, sizeof(wifi_config.sta.password));

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
        if (esp_netif_get_ip_info(netif, &ip_info) == ESP_OK && ip_info.ip.addr != 0) {
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
    stop_sniffer_and_connect("OnePlus Nord CE4 4C5E", "wmwg5556");
    esp_netif_ip_info_t ip_info;
esp_netif_get_ip_info(esp_netif_get_handle_from_ifkey("WIFI_STA_DEF"), &ip_info);
ESP_LOGI("NET", "IP: " IPSTR, IP2STR(&ip_info.ip));
esp_netif_dns_info_t dns;
esp_netif_t *sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
esp_netif_get_dns_info(sta_netif, ESP_NETIF_DNS_MAIN, &dns);
ESP_LOGI("DNS", "DNS Server: " IPSTR, IP2STR(&dns.ip.u_addr.ip4));

    ESP_LOGI("TG", "Sending file to Telegram: %s", file_path);
    if (!file_path || strlen(file_path) == 0) {
        ESP_LOGE("TG", "Invalid file path provided.");
        return;
    }
    ESP_LOGI("TG", "Using bot token: %s", TELEGRAM_BOT_TOKEN);
    ESP_LOGI("TG", "Using chat ID: %s", TELEGRAM_CHAT_ID);
    char url[256];
    snprintf(url, sizeof(url),
             "https://api.telegram.org/bot%s/sendDocument", TELEGRAM_BOT_TOKEN);
    ESP_LOGI("TG", "Telegram URL: %s", url);
esp_http_client_config_t config = {
    .url = url,
      .transport_type = HTTP_TRANSPORT_OVER_SSL,
    .crt_bundle_attach = esp_crt_bundle_attach,
       .method = HTTP_METHOD_POST,
        .timeout_ms = 30000  // Set to 30 seconds
};



    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_http_client_set_method(client, HTTP_METHOD_POST);

    // Build multipart form-data
    const char *boundary = "----ESP32Boundary";
    char header[256];
    snprintf(header, sizeof(header),
             "multipart/form-data; boundary=%s", boundary);
    esp_http_client_set_header(client, "Content-Type", header);

    FILE *file = fopen(file_path, "rb");
    if (!file) {
        ESP_LOGE("TG", "Failed to open file: %s", file_path);
        return;
    }

    // Start form-data
    char start_part[512];
    snprintf(start_part, sizeof(start_part),
             "--%s\r\n"
             "Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n"
             "%s\r\n"
             "--%s\r\n"
             "Content-Disposition: form-data; name=\"document\"; filename=\"capture.pcap\"\r\n"
             "Content-Type: application/octet-stream\r\n\r\n",
             boundary, TELEGRAM_CHAT_ID, boundary);

    esp_http_client_write(client, start_part, strlen(start_part));

    // Write file content
    char buf[512];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), file)) > 0) {
        esp_http_client_write(client, buf, n);
    }
    fclose(file);

    // End form-data
    char end_part[64];
    snprintf(end_part, sizeof(end_part), "\r\n--%s--\r\n", boundary);
    esp_http_client_write(client, end_part, strlen(end_part));
    // Send request
    esp_err_t err = esp_http_client_perform(client);
    int len = esp_http_client_get_content_length(client);
char *resp = malloc(len + 1);
esp_http_client_read(client, resp, len);
resp[len] = '\0';
ESP_LOGE("TG", "Telegram says: %s", resp);
free(resp);

    if (err == ESP_OK) {
        ESP_LOGI("TG", "File sent! Status = %d", esp_http_client_get_status_code(client));
    } else {
        ESP_LOGE("TG", "Error sending file: %s", esp_err_to_name(err));
    }

    esp_http_client_cleanup(client);
}
