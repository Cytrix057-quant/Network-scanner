import socket
import subprocess
import sys
import os
import datetime
from scapy.all import ARP, Ether, srp, sr, conf, IP, ICMP # Import Scapy components
import requests

def get_target_input():
    """
    Prompts the user to enter the target IP address or hostname.
    """
    while True:
        target = input("Enter target IP address or hostname (e.g., 192.168.1.1 or example.com): ").strip()
        if target:
            return target
        else:
            print("Target cannot be empty. Please try again.")

def get_port_range_input():
    """
    Prompts the user to enter the port range for scanning.
    """
    while True:
        try:
            start_port = int(input("Enter the starting port for scan (e.g., 1): "))
            end_port = int(input("Enter the ending port for scan (e.g., 1024): "))

            if 1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port:
                return start_port, end_port
            else:
                print("Invalid port range. Ports must be between 1 and 65535, and start port must be less than or equal to end port.")
        except ValueError:
            print("Invalid input. Please enter valid numbers for ports.")

def host_is_up(target_ip, timeout=1):
    """
    Checks if a host is up using both TCP connection attempts and ICMP ping.
    Returns True if reachable, False otherwise.
    Requires Scapy for ICMP ping.
    """
    print(f"[*] Checking if host {target_ip} is UP (TCP ports & ICMP ping)...")

    # 1. TCP Port Check (existing logic)
    common_ports = [80, 443, 22, 23, 21, 53]
    for port in common_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((target_ip, port))
            s.close()
            if result == 0:
                print(f"[+] Host {target_ip} is UP (TCP Port {port} reachable).")
                return True
        except socket.gaierror:
            print(f"[-] Hostname could not be resolved: {target_ip}")
            return False
        except socket.error:
            pass # Ignore specific socket errors for individual port attempts

    # 2. ICMP Ping Check (NEW)
    try:
        # Create an IP packet with the destination target_ip
        # Layer 3 (IP) over Layer 2 (Ethernet) is handled by Scapy's send/sr functions for us
        # We construct an IP packet containing an ICMP echo request
        ping_packet = IP(dst=target_ip)/ICMP()

        # Send the packet and wait for a response
        # sr() returns (answered packets, unanswered packets)
        # verbose=False to suppress Scapy's default output
        # timeout for how long to wait for a response
        ans, unans = sr(ping_packet, timeout=timeout, verbose=False)

        if ans:
            # If there's any answer, it means the host responded to ping
            for sent, received in ans:
                if received.haslayer(ICMP) and received[ICMP].type == 0: # ICMP type 0 is Echo Reply
                    print(f"[+] Host {target_ip} is UP (Responded to ICMP Echo Reply).")
                    return True
        
    except ImportError:
        print("[!] Scapy not installed for ICMP ping. Only relying on TCP port checks.")
        # If Scapy isn't installed, we can't do ICMP ping, so just continue
        # and let the final message be printed if TCP failed too.
    except PermissionError:
        print("[!] Permission Denied for ICMP ping: Requires root/administrator privileges.")
        print("    (Try running with 'sudo python network_scanner.py')")
        # Continue and let the final message be printed if TCP failed too.
    except Exception as e:
        print(f"[-] An error occurred during ICMP ping check: {e}")
        # Continue and let the final message be printed if TCP failed too.

    print(f"[-] Host {target_ip} appears to be DOWN (No common TCP ports open, no ICMP echo reply).")
    return False

def port_scan(target_ip, start_port, end_port, timeout=1):
    """
    Performs a TCP port scan on the target IP for the specified port range.
    Prints open ports.
    """
    print(f"\n[*] Starting TCP Port Scan on {target_ip} from port {start_port} to {end_port}...")
    open_ports = []

    for port in range(start_port, end_port + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)

            result = s.connect_ex((target_ip, port))

            if result == 0:
                print(f"[+] Port {port} is OPEN")
                open_ports.append(port)
            s.close()
        except KeyboardInterrupt:
            print("\n[-] Port scan interrupted by user.")
            break
        except socket.error:
            pass
    
    if not open_ports:
        print(f"[-] No open ports found in the range {start_port}-{end_port}.")
    else:
        print(f"\n[+] Scan complete. Open ports found: {open_ports}")

    return open_ports

def grab_banner(target_ip, port, timeout=2):
    """
    Attempts to grab a service banner from the specified port.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target_ip, port))

        # For HTTP, we might need to send a GET request
        if port == 80 or port == 443: # Common web ports
            s.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n") # Send a basic HTTP GET request
            # Note: For real-world HTTPS (port 443), you'd need the 'ssl' module.
            # This example only attempts a simple TCP connection and read for 443 too.

        banner = s.recv(1024).decode('utf-8', errors='ignore').strip() # Receive up to 1024 bytes
        s.close()
        if banner:
            # Only print a portion of the banner to avoid overwhelming output
            # and remove common unwanted characters like newlines and carriage returns
            clean_banner = banner.replace('\r', '').replace('\n', ' ')
            print(f"    [-> Banner for Port {port}]: {clean_banner[:100]}...") # Print first 100 chars
        else:
            print(f"    [-> No banner received for Port {port}]")
    except socket.timeout:
        print(f"    [-> Timeout: No banner received for Port {port}]")
    except ConnectionResetError:
        print(f"    [-> Connection Reset: Port {port} closed unexpectedly or no banner]")
    except socket.error as e:
        # print(f"    [-> Socket Error for Port {port}]: {e}") # For debugging
        print(f"    [-> Could not grab banner for Port {port}]")
    except Exception as e:
        print(f"    [-> An unexpected error occurred for Port {port} banner]: {e}")

def get_local_ip_and_mask():
    """
    Gets the local machine's IP address and attempts to determine the network mask.
    Returns (ip_address, subnet_mask) or (None, None) on failure.
    """
    try:
        # Get host's IP address by connecting to an external server (doesn't send data)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)) # Connect to a public DNS server
        local_ip = s.getsockname()[0]
        s.close()

        # Attempt to get subnet mask. This is tricky with standard library.
        # Scapy's conf.route.route method is more reliable for network interface info.
        # For simplicity, we'll try to infer a common /24 if not directly obtainable,
        # or rely on Scapy's route info later.
        print(f"[*] Detected local IP: {local_ip}")
        return local_ip
    except Exception as e:
        print(f"[-] Could not determine local IP address: {e}")
        return None

# --- Existing get_local_ip_and_mask ---
def get_local_ip_and_mask():
    """
    Gets the local machine's IP address.
    Returns ip_address or None on failure.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return None

def grab_mac_vendor(mac_address):
    """
    Attempts to look up the vendor (manufacturer) of a device
    using its MAC address via an online API.
    """
    if not mac_address or mac_address == "N/A":
        return "Unknown"

    # Normalize MAC address (remove colons/dashes for some APIs)
    clean_mac = mac_address.replace(":", "").replace("-", "").upper()
    
    # Using macvendors.com (often works without API key for basic lookups)
    url = f"https://api.macvendors.com/{clean_mac}"
    
    try:
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            return response.text.strip() # macvendors.com returns plain text vendor name
        elif response.status_code == 404:
            return "Vendor Not Found"
        else:
            # For other APIs returning JSON, you'd parse:
            # data = response.json()
            # return data.get("vendorDetails", {}).get("companyName", "Unknown")
            return f"API Error: {response.status_code}"
    except requests.exceptions.Timeout:
        return "API Timeout"
    except requests.exceptions.RequestException as e:
        # print(f"DEBUG: MAC vendor API request failed: {e}") # For debugging
        return "API Request Failed"
    except Exception as e:
        return f"Unexpected Error: {e}"

def arp_scan_local_network(interface=None, timeout=2):
    """
    Performs an ARP scan on the local network to discover active hosts.
    Requires Scapy and often root/admin privileges.
    """
    print("\n[*] Starting Local Network ARP Scan...")
    print("    (This feature requires 'scapy' and often root/admin privileges.)")

    try:
        local_ip = get_local_ip_and_mask()
        if not local_ip:
            print("[-] Failed to get local IP address. Cannot perform ARP scan.")
            return []

        interface_name = interface
        target_network = ""

        if not interface_name:
            try:
                # Try to get interface and network from Scapy's route
                iface_info = conf.route.route(local_ip)
                if iface_info and len(iface_info) > 3: # Ensure enough elements
                    # network_address = iface_info[0] # This is the network address (e.g., 192.168.1.0)
                    # netmask = iface_info[1] # This is the subnet mask (e.g., 255.255.255.0)
                    # netmask_bits = sum([bin(int(x)).count('1') for x in netmask.split('.')])
                    # target_network = f"{network_address}/{netmask_bits}"
                    # Use Scapy's built-in way to get the network from interface
                    interface_name = iface_info[3] # Get the interface name
                    # Scapy's `get_if_addr` and `get_if_hwaddr` can be used here.
                    # Or even simpler, for a given interface, Scapy can get its network.
                    # Let's rely on conf.route if it works, otherwise fallback.

                    # A more direct way to get network from Scapy with interface name:
                    # `conf.iface` is often the default active interface.
                    # Use a common /24 for the local_ip if detailed interface info is hard to parse
                    target_network = f"{local_ip.rsplit('.', 1)[0]}.0/24" # Fallback to /24 from local IP
                    print(f"[*] Auto-detected network interface (might be default): {interface_name}")
                    print(f"[*] Assuming local network range: {target_network}")
                else:
                    print(f"[-] Could not determine network interface/range for {local_ip} via Scapy route.")
                    print("    Attempting a common /24 scan based on detected IP...")
                    target_network = f"{local_ip.rsplit('.', 1)[0]}.0/24" # Fallback to /24
                    interface_name = conf.iface # Scapy's default interface
            except Exception as e:
                print(f"[-] Error auto-detecting network: {e}")
                print("    Attempting a common /24 scan based on detected IP...")
                target_network = f"{local_ip.rsplit('.', 1)[0]}.0/24" # Fallback to /24
                interface_name = conf.iface # Scapy's default interface
        else:
            # If interface is explicitly provided, we still need to derive the network for it.
            # For simplicity, we'll assume the user-provided interface has an IP and use its /24.
            # A more advanced tool would use netifaces or platform specific commands to verify.
            print(f"[*] Using specified interface: '{interface_name}'")
            # This is a bit of a guess, but for a local network, /24 is common.
            target_network = f"{local_ip.rsplit('.', 1)[0]}.0/24" 
            print(f"[*] Assuming network for specified interface: {target_network}")


        arp_request = ARP(pdst=target_network)
        broadcast_ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast_ether / arp_request

        ans, unans = srp(arp_request_broadcast, timeout=timeout, verbose=False, iface=interface_name)

        active_hosts = []
        print("\n[+] Active Devices Found:")
        print("---------------------------------------------------------------------------------")
        print(f"{'IP Address':<16} {'MAC Address':<18} {'Hostname':<30} {'Manufacturer':<30}")
        print("---------------------------------------------------------------------------------")
        
        for sent, received in ans:
            ip = received.psrc
            mac = received.hwsrc
            hostname = "N/A"
            vendor = "N/A"
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                pass
            
            vendor = grab_mac_vendor(mac) # Call the new function here!

            active_hosts.append({"ip": ip, "mac": mac, "hostname": hostname, "vendor": vendor})
            print(f"{ip:<16} {mac:<18} {hostname:<30} {vendor:<30}")
        
        print("---------------------------------------------------------------------------------")

        if not active_hosts:
            print("[-] No active hosts found on the local network via ARP scan.")
        
        return active_hosts

    except PermissionError:
        print("\n[!] Permission Denied: ARP scan requires root/administrator privileges.")
        print("    Please run the script with 'sudo python network_scanner.py' on Linux/macOS.")
        print("    On Windows, ensure Npcap is installed and running, and run as administrator.")
        return []
    except ImportError:
        print("\n[!] Scapy or Requests library not found. Please install them using: pip install scapy requests")
        return []
    except Exception as e:
        print(f"\n[!] An error occurred during ARP scan: {e}")
        return []

def main():
    print("---------------------------------------")
    print("  Python Network Reconnaissance Tool   ")
    print("---------------------------------------")

    start_time = datetime.datetime.now()

    # Offer scan choices
    print("\nSelect scan type:")
    print("1. Scan a single target (Host Discovery, Port Scan, Banner Grabbing)")
    print("2. Scan local network for all connected devices (ARP Scan)")
    
    scan_choice = input("Enter choice (1 or 2): ").strip()

    if scan_choice == '1':
        target = get_target_input()

        print(f"\n[*] Starting scan on target: {target}")

        try:
            target_ip = socket.gethostbyname(target)
            print(f"[*] Resolved {target} to IP: {target_ip}")
        except socket.gaierror:
            print(f"[-] Error: Could not resolve hostname '{target}'. Exiting.")
            sys.exit(1)

        print("\n[*] Performing Host Discovery...")
        if not host_is_up(target_ip):
            print(f"[-] Host {target_ip} is not reachable. Skipping further scans.")
            sys.exit(0)

        start_port, end_port = get_port_range_input()

        open_ports = port_scan(target_ip, start_port, end_port)

        if open_ports:
            print("\n[*] Attempting Service Banner Grabbing for Open Ports...")
            for port in open_ports:
                grab_banner(target_ip, port)
        else:
            print("\n[-] No open ports found, skipping banner grabbing.")

    elif scan_choice == '2':
        # ARP Scan on local network
        # You might want to allow the user to specify an interface, for now, Scapy tries to auto-detect.
        # conf.iface can be explicitly set if needed: conf.iface = "eth0"
        arp_scan_local_network()

    else:
        print("[-] Invalid choice. Exiting.")
        sys.exit(1)

    end_time = datetime.datetime.now()
    total_time = end_time - start_time
    print(f"\n[+] Scan finished in {total_time}.")

    # Service Banner Grabbing
    if open_ports:
        print("\n[*] Attempting Service Banner Grabbing for Open Ports...")
        for port in open_ports:
            grab_banner(target_ip, port)
    else:
        print("\n[-] No open ports found, skipping banner grabbing.")

    end_time = datetime.datetime.now()
    total_time = end_time - start_time
    print(f"\n[+] Scan finished in {total_time}.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] Exiting program.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] An error occured: {e}")
        sys.exit(1)