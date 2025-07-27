#include "esp_spiffs.h"
#include "esp_log.h"
#include <sys/time.h>
#include "base64.h"

struct pcap_hdr_s {
    uint32_t magic_number;   // 0xa1b2c3d4
    uint16_t version_major;  // 2
    uint16_t version_minor;  // 4
    int32_t  thiszone;       // GMT offset
    uint32_t sigfigs;        // accuracy
    uint32_t snaplen;        // max length of captured packets
    uint32_t network;        // data link type (1 = Ethernet, 105 = IEEE 802.11)
};
struct pcaprec_hdr_s {
    uint32_t ts_sec;   // timestamp seconds
    uint32_t ts_usec;  // timestamp microseconds
    uint32_t incl_len; // number of octets saved in file
    uint32_t orig_len; // original length of packet
};

 bool writer_enabled = false;
 FILE *pcap_file = NULL;


void write_pcap_header(FILE *f) {
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

void start_pcap_writer(void) {
    pcap_file = fopen("/spiffs/capture.pcap", "wb");
    if (!pcap_file) {
        ESP_LOGE("PCAP", "Failed to open file for writing");
        return;
    }
    write_pcap_header(pcap_file);
    writer_enabled = true;
    ESP_LOGI("PCAP", "PCAP file created with header");
}

void write_pcap_packet(const uint8_t *data, uint32_t len) {
    if (!pcap_file) return;
 //   ESP_LOGI("PCAP", "File size after write: %ld bytes", ftell(pcap_file));
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
}
void close_pcap_writer(void) {
    if (pcap_file) {
        fclose(pcap_file);
        pcap_file = NULL;
        ESP_LOGI("PCAP", "PCAP file closed");
    }
    writer_enabled = false;
    dump_file_one_shot(); // Dump the file in Base64 format
}
bool is_writer_enabled() {
    return writer_enabled;
}

FILE *get_pcap_file() {
    return pcap_file;
}
