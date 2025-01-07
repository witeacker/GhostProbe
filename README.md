# GhostProbe
## Overview
This tool monitors wireless networks for de-authentication, dissociation attacks, and Rogue AP attacks. It captures and analyzes packets transmitted over the network to detect these attacks in real-time.

### Features
- **Deauthentication Attack Detection:** Detects and logs deauthentication attacks targeting access points and clients.
- **Dissociation Attack Detection:** Detects and logs dissociation attacks targeting wireless clients.
- **Rogue Access Point Detection:** Detects and logs rogue access points broadcasting a network with the same SSID as legitimate access points but with a different BSSID.
- **Packet Sniffing:** Uses `scapy` to sniff wireless packets and identify attacks in real-time.
- **Log Rotation:** Logs attack messages to a .txt file.

### Tested on Kali Linux

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
3. **Ensure your wireless card supports monitor mode**

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
