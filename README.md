# GhostProbe
## Overview
This tool monitors wireless networks for specific security threats, such as Deauthentication attacks, Dissociation attacks, and Rogue Access Points. It captures and analyzes packets transmitted over the network to detect these attacks in real-time. The tool is intended for network administrators and cybersecurity professionals who want to monitor and secure wireless networks.

### Features
- **Deauthentication Attack Detection:** Detects and logs deauthentication attacks targeting access points and clients.
- **Dissociation Attack Detection:** Detects and logs dissociation attacks targeting wireless clients.
- **Rogue Access Point Detection:** Detects and logs rogue access points broadcasting a network with the same SSID as legitimate access points but with a different BSSID.
- **Packet Sniffing:** Uses `scapy` to sniff wireless packets and identify attacks in real-time.
- **Log Rotation:** Logs attack messages to a file with automatic rotation when the file size exceeds 10 MB.
- **Interface Management:** This allows users to select and switch between wireless interfaces in monitor mode for packet sniffing.

### Tested on Kali Linux

## Requirements
Before you begin, ensure you have the following installed:
- **Python 3.x**: The script is written in Python.
- **scapy**: Python library for packet crafting and sniffing. Install with `pip install scapy`.
- **termcolor**: For colorful terminal output. Install with `pip install termcolor`.
- **airmon-ng**: A tool for managing wireless interfaces on Linux. It is used to enable monitor mode.
- **iwconfig**: A Linux tool for configuring wireless interfaces.
- **root privileges**: You need to run the script with root privileges to manage interfaces and sniff packets.

## Installation
1. **Clone the repository:**
   ```bash
   git clone https://github.com/witeackr/GhostProbe.git
   cd GhostProbe
   ```
2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
3. **Ensure your wireless card supports monitor mode** and is compatible with the tools used (e.g., `airmon-ng`, `iwconfig`).

## Usage
### Starting the Tool
1. **Select an interface** to monitor:
   - Run the script:
     ```bash
     sudo python GhostProbe.py
     ```
2. **Choose the wireless interface** to use from the available options.
3. **Monitor for attacks**:
   - The tool will start sniffing packets on the selected interface and display alerts for any detected attacks (Deauth, Dissociation, Rogue AP).
4. **Stopping the tool**:
   - Press `Ctrl+C` to stop the sniffing process, which will also restore the interface to its original mode.

## Contribution
Contributions are welcome! If you'd like to contribute to the project.
## Reach me on [Linkedin](https://www.linkedin.com/in/samuel-ajayi-opemipo)
