#include <stdint.h>
#include <stdbool.h>
#include <stdio.h> 
void start_pcap_writer(void);

void write_pcap_packet(const uint8_t *data, uint32_t len);

void close_pcap_writer(void);

bool  is_writer_enabled(void);

FILE *get_pcap_file(void);

void close_task(void *arg);

TaskHandle_t close_task_handle = NULL;