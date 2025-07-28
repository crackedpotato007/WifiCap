# 🔐 ESP32 Wi-Fi Handshake Sniffer & PCAP Downloader

A **fully self-contained ESP32 project** that:

- Captures **all 2.4 GHz Wi-Fi traffic** in range
- Extracts **WPA2 4-way handshakes**
- Saves the raw capture as a **PCAP file**
- Hosts a **downloadable web interface via an ESP32 Access Point**

Perfect for **Wi-Fi security research**, **pentesting labs**, and **educational projects**.

---

## ✨ Features

✔ Captures **all Wi-Fi traffic** in promiscuous mode  
✔ Filters and detects **WPA2 EAPOL handshakes**  
✔ Saves captured packets into a **.pcap file** (Wireshark compatible)  
✔ Creates an **Access Point (ESP32_AP / password: 12345678)**  
✔ Simple **web interface** to download the PCAP file  
✔ Works standalone — **no external tools or PC needed during capture**

---

## ⚡ Getting Started

### ✅ Requirements

- **ESP32 Dev Board** (WROOM/WROVER)
- **PlatformIO** (or ESP-IDF)
- Basic Wi-Fi knowledge

---

### 🔧 Setup & Flash

1. **Clone the repository**

   ```bash
   git clone https://github.com/crackedpotato007/WifiCap
   cd esp32-wifi-capture
   ```

2. **Build & upload**

   ```bash
   pio run --target upload
   ```

3. **Open Serial Monitor(Optional)**

   ```bash
   pio device monitor
   ```

4. **Connect to the ESP32_AP**
5. **Open your browser** and go to `http://192.168.4.1`

---

## 📜 How It Works

- ESP32 switches to **promiscuous mode**
- Listens for **all 2.4 GHz Wi-Fi traffic**
- Loops through all available APs
- Finds all stations
- Deauths stations to capture handshakes
- Captures **all 802.11 frames** for the AP right before the deauth and 10 seconds after
- Writes packets into a **.pcap file** in SPIFFS
- Starts **ESP32_AP** (default password: `12345678`)
- Hosts a **web server** at `http://192.168.4.1` to download the PCAP

---

## 🖼 Web Interface

Once the AP is up:

- Connect to **ESP32_AP**
- Open `http://192.168.4.1` in your browser
- Download your `capture.pcap` file

---

## ⚠️ Legal Disclaimer

This project is for **educational and authorized security testing only**.
Capturing packets from networks without permission is **illegal and unethical**.

---

## 🚀 Roadmap

- ✅ Add **channel hopping** for better coverage
- ✅ Support **multiple PCAP files**
- 🔄 Add **real-time capture stats** on web UI
- 🔄 Add **handshake auto-extract to .hccapx**

---

## 🔗 Related Tools

- [Wireshark](https://www.wireshark.org/) to analyze PCAPs
- [Hashcat](https://hashcat.net/hashcat/) for WPA cracking
