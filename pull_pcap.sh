PORT=/dev/ttyUSB0 && \
esptool.py --chip esp32 --port $PORT --baud 921600 read_flash 0x110000 0x200000 spiffs_dump.bin && \
mkdir -p spiffs_out && \
mkspiffs -u output_dir spiffs_dump.bin 