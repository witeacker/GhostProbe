import os
import time
import subprocess
import threading
import signal
from scapy.all import sniff, Dot11, Dot11Deauth, Dot11Disas, Dot11Beacon
from termcolor import colored

# Log file setup
LOG_FILE = "deauth_log.txt"
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB (rotate logs if larger)

# Global container to track SSIDs and BSSIDs
seen_aps = {}

# Log Message Function
def log_message(message):
    """Log a message to the log file with rotation."""
    if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > MAX_LOG_SIZE:
        os.rename(LOG_FILE, f"{LOG_FILE}.old")
    with open(LOG_FILE, "a") as log:
        log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")

# List interfaces
def list_interfaces():
    """List available wireless interfaces."""
    try:
        result = subprocess.run(["iwconfig"], capture_output=True, text=True, check=True)
        interfaces = []
        for line in result.stdout.splitlines():
            if "IEEE 802.11" in line:
                iface = line.split()[0]
                interfaces.append(iface)
        return interfaces
    except subprocess.CalledProcessError as e:
        print(colored(f"Error listing interfaces: {e.stderr}", "red"))
        return []

# Check if the interface is already in monitor mode
def is_monitor_mode(interface):
    """Check if the interface is in monitor mode."""
    try:
        result = subprocess.run(["iwconfig", interface], capture_output=True, text=True, check=True)
        return "Mode:Monitor" in result.stdout
    except subprocess.CalledProcessError:
        return False

# Enable Monitor Mode
def enable_monitor_mode(interface):
    """Enable monitor mode on the selected interface."""
    if is_monitor_mode(interface):
        print(colored(f"{interface} is already in monitor mode.", "yellow"))
        return interface
    try:
        print(f"Enabling monitor mode on {interface}...")
        subprocess.run(["sudo", "airmon-ng", "start", interface], check=True)
        return f"{interface}mon"
    except subprocess.CalledProcessError as e:
        print(colored(f"Error enabling monitor mode: {e.stderr}", "red"))
        return None

# Disable Monitor Mode
def disable_monitor_mode(interface):
    """Disable monitor mode and restore managed mode."""
    try:
        print(f"Restoring {interface} to managed mode...")
        subprocess.run(["sudo", "airmon-ng", "stop", interface], check=True)
    except subprocess.CalledProcessError as e:
        print(colored(f"Error disabling monitor mode: {e.stderr}", "red"))

# Detect Deauth Attack
def detect_deauth(packet):
    if packet.haslayer(Dot11Deauth):
        bssid = packet.addr1
        attacker = packet.addr2
        message = f"Deauth detected! AP: {bssid}, Attacker: {attacker}"
        print(colored(f"[ALERT] {message}", "red"))
        log_message(message)

# Detect Dissociation Attack
def detect_dissoc(packet):
    if packet.haslayer(Dot11Disas):
        bssid = packet.addr1
        attacker = packet.addr2
        message = f"Dissociation detected! AP: {bssid}, Attacker: {attacker}"
        print(colored(f"[ALERT] {message}", "red"))
        log_message(message)

# Detect Rogue AP
def detect_rogue_ap(packet):
    if packet.haslayer(Dot11Beacon):
        ssid = packet.info.decode()
        bssid = packet.addr3
        if ssid in seen_aps and seen_aps[ssid] != bssid:
            message = f"Rogue AP detected! SSID '{ssid}' with different BSSID: {bssid}"
            print(colored(f"[ALERT] {message}", "yellow"))
            log_message(message)
        else:
            seen_aps[ssid] = bssid

# Detect multiple attacks
def detect_attacks(packet):
    detect_deauth(packet)
    detect_dissoc(packet)
    detect_rogue_ap(packet)

# Sniff packets on an interface
def sniff_interface(interface):
    print(f"Sniffing on interface {interface}...")
    try:
        sniff(iface=interface, prn=detect_attacks, store=0)
    except Exception as e:
        log_message(f"Error while sniffing on {interface}: {str(e)}")
        print(colored(f"Sniffing error: {e}", "red"))

# Signal handler to stop sniffing gracefully
def stop_sniffing(signum, frame):
    print(colored("Stopping sniffing... Restoring interface.", "green"))
    disable_monitor_mode(mon_interface)
    exit(0)

# Start sniffing on multiple interfaces
def start_sniffing_on_multiple_interfaces():
    interfaces = list_interfaces()
    if not interfaces:
        print(colored("No wireless interfaces found. Ensure your wireless card is connected.", "red"))
        return

    print("Available Wireless Interfaces:")
    for idx, iface in enumerate(interfaces, start=1):
        print(f"{idx}. {iface}")

    try:
        choice = int(input("Select an interface (e.g., 1): "))
        if choice < 1 or choice > len(interfaces):
            raise ValueError("Invalid choice")
        selected_interface = interfaces[choice - 1]
    except ValueError as e:
        print(colored(f"Invalid selection: {e}. Please try again.", "red"))
        return

    global mon_interface
    mon_interface = enable_monitor_mode(selected_interface)
    if not mon_interface:
        print(colored("Failed to enable monitor mode. Exiting...", "red"))
        return

    # Register signal handler
    signal.signal(signal.SIGINT, stop_sniffing)

    sniff_thread = threading.Thread(target=sniff_interface, args=(mon_interface,))
    sniff_thread.start()
    sniff_thread.join()

if __name__ == "__main__":
    start_sniffing_on_multiple_interfaces()
