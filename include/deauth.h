#ifndef DEAUTH_H
#define DEAUTH_H
#include <stdint.h>

void send_deauth_packet(const uint8_t *ap_bssid, const uint8_t *client_mac);

#endif
