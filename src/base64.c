#include "mbedtls/base64.h"
#include "esp_log.h"
#include "esp_spiffs.h"
#include <stdio.h>
#define CHUNK_SIZE 512

void dump_file_one_shot(void) {
    FILE *f = fopen("/spiffs/capture.pcap", "rb");
    if (!f) {
        ESP_LOGE("DUMP", "Failed to open capture file");
        return;
    }

    uint8_t raw_buf[CHUNK_SIZE];
    unsigned char base64_buf[(CHUNK_SIZE * 4 / 3) + 4];
    size_t bytes_read, out_len;

    ESP_LOGI("DUMP", "----- BEGIN BASE64 PCAP -----");
    while ((bytes_read = fread(raw_buf, 1, CHUNK_SIZE, f)) > 0) {
        out_len = 0;
        int ret = mbedtls_base64_encode(base64_buf, sizeof(base64_buf), &out_len,
                                        raw_buf, bytes_read);
        if (ret == 0) {
            base64_buf[out_len] = '\0';
            ESP_LOGI("DUMP", "%s", base64_buf);
        } else {
            ESP_LOGE("DUMP", "Base64 encode failed: %d", ret);
            break;
        }
    }
    ESP_LOGI("DUMP", "----- END BASE64 PCAP -----");

    fclose(f);
}
