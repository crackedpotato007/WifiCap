#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_http_server.h"
#include <dirent.h>
#include <string.h>
#include "lwip/ip4_addr.h"

static const char *TAG = "HTTP_AP";

#define AP_SSID "ESP32_AP"
#define AP_PASS "12345678"

// Serve file list
esp_err_t root_handler(httpd_req_t *req) {
    DIR *dir = opendir("/spiffs");
    if (!dir) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    char buffer[512] = "<h2>Files:</h2><ul>";
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        strcat(buffer, "<li><a href=\"/download?file=");
        strcat(buffer, entry->d_name);
        strcat(buffer, "\">");
        strcat(buffer, entry->d_name);
        strcat(buffer, "</a></li>");
    }
    strcat(buffer, "</ul>");
    closedir(dir);

    httpd_resp_send(req, buffer, strlen(buffer));
    return ESP_OK;
}

// Serve actual file
esp_err_t download_handler(httpd_req_t *req) {
    char filepath[64] = "/spiffs/";
    char param[32];

    if (httpd_req_get_url_query_len(req) > 0) {
        char *query = malloc(httpd_req_get_url_query_len(req) + 1);
        httpd_req_get_url_query_str(req, query, httpd_req_get_url_query_len(req) + 1);
        httpd_query_key_value(query, "file", param, sizeof(param));
        free(query);
    } else {
        httpd_resp_send_404(req);
        return ESP_FAIL;
    }

    strcat(filepath, param);
    FILE *f = fopen(filepath, "rb");
    if (!f) {
        httpd_resp_send_404(req);
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "application/octet-stream");
    char buf[512];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        httpd_resp_send_chunk(req, buf, n);
    }
    fclose(f);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

// Start AP and server
void start_file_server_ap() {
    ESP_LOGI(TAG, "Switching to AP mode...");
    esp_wifi_set_promiscuous(false);
    esp_wifi_stop();
    esp_netif_t *netif_ap = esp_netif_create_default_wifi_ap();
esp_netif_dhcps_stop(netif_ap); // Stop in case it's running
esp_netif_ip_info_t ip_info;
IP4_ADDR(&ip_info.ip, 192,168,4,1);
IP4_ADDR(&ip_info.gw, 192,168,4,1);
IP4_ADDR(&ip_info.netmask, 255,255,255,0);
esp_netif_set_ip_info(netif_ap, &ip_info);
esp_netif_dhcps_start(netif_ap); // Start DHCP server


    // Configure AP
    wifi_config_t ap_config = {
        .ap = {
            .ssid = AP_SSID,
            .ssid_len = strlen(AP_SSID),
            .channel = 1,
            .password = AP_PASS,
            .max_connection = 4,
            .authmode = WIFI_AUTH_WPA_WPA2_PSK
        }
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "AP started: SSID=%s, PASS=%s", AP_SSID, AP_PASS);

    // Start HTTP server
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    if (httpd_start(&server, &config) == ESP_OK) {
        httpd_uri_t root = {.uri = "/", .method = HTTP_GET, .handler = root_handler};
        httpd_register_uri_handler(server, &root);

        httpd_uri_t download = {.uri = "/download", .method = HTTP_GET, .handler = download_handler};
        httpd_register_uri_handler(server, &download);
    }
}
