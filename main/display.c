#include <driver/i2c_master.h> // ESP-IDF I2C master driver
#include <esp_ssd1306.h>       // SSD1306 component header

/* I2C Master Configuration */
static i2c_master_bus_config_t i2c_master_bus_config = {
    .i2c_port = I2C_NUM_0,
    .scl_io_num = GPIO_NUM_22,
    .sda_io_num = GPIO_NUM_21,
    .clk_source = I2C_CLK_SRC_DEFAULT,
    .glitch_ignore_cnt = 7,
    .flags.enable_internal_pullup = true};
static i2c_master_bus_handle_t i2c_master_bus;

/* SSD1306 */
static const i2c_ssd1306_config_t i2c_ssd1306_config = {
    .i2c_device_address = 0x3C,
    .i2c_scl_speed_hz = 400000,
    .width = 128,
    .height = 64,
    .wise = SSD1306_TOP_TO_BOTTOM};
static i2c_ssd1306_handle_t i2c_ssd1306;

static char *TAG = "DISPLAY";

void init_display() {
  // Initialize I2C master bus
  ESP_ERROR_CHECK(i2c_new_master_bus(&i2c_master_bus_config, &i2c_master_bus));
  ESP_ERROR_CHECK(
      i2c_ssd1306_init(i2c_master_bus, &i2c_ssd1306_config, &i2c_ssd1306));
  ESP_LOGI(TAG, "Display initialized successfully");
}

void draw_wrapped_text(int x, int y, const char *text, int line_height) {
  int max_chars_per_line = 16;
  int line = 0;
  ESP_ERROR_CHECK_WITHOUT_ABORT(i2c_ssd1306_buffer_fill(&i2c_ssd1306, false));
  while (*text) {
    char buf[64] = {0};
    int i = 0;

    // Temporary pointer to mark the last safe split (space)
    const char *last_space = NULL;
    int last_space_i = -1;

    // Fill buffer word by word
    while (*text && i < max_chars_per_line) {
      buf[i] = *text;

      if (*text == ' ') {
        last_space = text;
        last_space_i = i;
      }

      i++;
      text++;
    }

    // If we hit mid-word, rewind to last space
    if (*text && last_space) {
      int rewind = i - last_space_i - 1;
      text -= rewind;
      i = last_space_i; // Truncate at last space
    }

    buf[i] = '\0';
    ESP_LOGI(TAG, "Drawing line %d: '%s'", line, buf);
    ESP_ERROR_CHECK_WITHOUT_ABORT(i2c_ssd1306_buffer_text(
        &i2c_ssd1306, x, y + (line * line_height), buf, false));
    ESP_ERROR_CHECK_WITHOUT_ABORT(i2c_ssd1306_buffer_to_ram(&i2c_ssd1306));

    line++;

    // Skip space after the word wrap (avoid leading spaces)
    while (*text == ' ')

      text++;
  }
}

void display(const char *message) { draw_wrapped_text(0, 0, message, 10); }