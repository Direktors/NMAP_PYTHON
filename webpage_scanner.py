import re
import socket
import random
import time
import requests
import subprocess  # Import the subprocess module
import whois

def get_url():
    url = input("Enter the webpage URL you want to scan: ").strip()
    return url

def validate_url(url):
    # Regular expression pattern for URL validation
    url_pattern = re.compile(
        r'^(?:http|https)://'  # Scheme
        r'(?:[\w-]+\.)*[\w-]+'  # Domain name
        r'(?:\:\d+)?'  # Optional port
        r'(?:\/\S*)?$'  # Optional path
    )
    if not re.match(url_pattern, url):
        print("Invalid URL format.")
        return False
    return True

def get_ip_address(url):
    try:
        host = re.search(r'(?<=://)(.*?)(?=/|$)', url).group(1)
        ip_address = socket.gethostbyname(host)
        return ip_address
    except Exception as e:
        print(f"Error resolving IP address: {e}")
        return None

def get_geolocation(ip_address):
    try:
        response = requests.get(f"https://ipinfo.io/{ip_address}/json")
        if response.status_code == 200:
            data = response.json()
            city = data.get("city", "Unknown")
            region = data.get("region", "Unknown")
            country = data.get("country", "Unknown")
            return f"{city}, {region}, {country}"
        else:
            return "Geolocation data not available"
    except Exception as e:
        print(f"Error fetching geolocation data: {e}")
        return "Error"

def get_random_user_agent():
    # List of user-agent strings to choose from
    USER_AGENT_STRINGS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.9999.999 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0",
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.9999.999 Safari/537.36 OPR/99.0.9999.999",
        # Add more user-agent strings as needed
    ]
    return random.choice(USER_AGENT_STRINGS)

def get_whois_info(ip_address):
    try:
        # Perform WHOIS lookup
        domain = whois.whois(ip_address)
        return str(domain)
    except Exception as e:
        return f"Error performing WHOIS lookup: {e}"

def scan_all_ports(url, protocols):
    # Extract host from the URL
    try:
        host = re.search(r'(?<=://)(.*?)(?=/|$)', url).group(1)
    except AttributeError:
        print("Invalid URL format.")
        return
    
    ip_address = get_ip_address(url)
    if ip_address:
        print(f"Webpage IP address: {ip_address}")
        geolocation = get_geolocation(ip_address)
        print(f"Geolocation: {geolocation}")
        
        # Reverse DNS Lookup
        try:
            reverse_dns = socket.gethostbyaddr(ip_address)[0]
            print(f"Reverse DNS Lookup: {reverse_dns}")
        except socket.herror:
            print("Reverse DNS Lookup: Not found")
        except Exception as e:
            print(f"Error performing Reverse DNS Lookup: {e}")

        # WHOIS Lookup
        whois_info = get_whois_info(ip_address)
        print("WHOIS Lookup:")
        print(whois_info)

    print(f"Scanning ports for {url} using automatic mode:")
    
    open_ports = []
    # Attempt to connect to ports for specified protocols
    for protocol in protocols:
        # Get ports for the current protocol
        ports = get_ports_for_protocol(protocol)
        
        # Scan ports for the current protocol
        for p in ports:
            # Initialize socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)  # Set socket timeout to 1 second

            try:
                # Set random user-agent string for each request
                headers = {"User-Agent": get_random_user_agent()}
                
                s.connect((host, p))
                print(f"Port {p} [{protocol}] is open on {host}")
                try:
                    banner = s.recv(4096).decode('utf-8')  # Increased buffer size
                    service_info = parse_banner(banner)
                    open_ports.append((p, protocol) + service_info)
                except ConnectionResetError:
                    print(f"Failed to retrieve banner for port {p}.")
            except (socket.timeout, ConnectionRefusedError):
                pass  # Port is closed, so no need to print a message
            except socket.gaierror:
                print("Error resolving host.")
            finally:
                s.close()  # Close the socket after each connection attempt
                
            # Introduce random delay between scan requests
            delay = random.uniform(0.5, 2.0)  # Random delay between 0.5 and 2.0 seconds
            time.sleep(delay)  # Sleep for the random delay before the next scan request
    
    return open_ports

def parse_banner(banner):
    # Initialize default values
    service_name = "Unknown"
    service_version = "Unknown"
    
    # Example: Parse SSH banner to extract service name and version
    if "SSH" in banner:
        service_name = "SSH"
        match = re.search(r'SSH-(\S+)', banner)
        if match:
            service_version = match.group(1)
    
    # Return the service name, version, and full banner text
    return service_name, service_version, banner.strip()

def get_ports_for_protocol(protocol):
    protocol_ports = {
        "FTP": [21, 2121],  # Standard and non-standard FTP ports
        "SSH": [22],
        "DNS": [53],
        "DHCP": [67, 68],
        "HTTP": [80, 8080],  # Standard and non-standard HTTP ports
        "SMTP": [25],
        "POP": [110],
        "HTTPS": [443, 8443],  # Standard and non-standard HTTPS ports
        "TELNET": [23],
        "GOPHER": [70],
        "IP": [],  # Excluding IP from all open port scanning
        "LDAP": [389],
        "SNMP": [161],
        "RDP": [3389],
        "IMAP": [143],
        "NTP": [123],
        "SMB": [445],
        "MYSQL": [3306],
        "POSTGRESQL": [5432],
        "FTPS": [990, 2121],  # Standard and non-standard FTPS ports
        "TCP": list(range(1, 1024)),  # Well-known TCP ports
        "UDP": list(range(1, 1024))   # Well-known UDP ports
    }
    return protocol_ports.get(protocol, [])

def main():
    url = get_url()
    if not url:
        print("No URL provided. Exiting.")
        return
    if not validate_url(url):
        return

    scan_all = input("Do you want to scan for all open ports (Y/N)? ").strip().upper()
    if scan_all == "Y":
        protocols_to_scan = ["FTP", "SSH", "DNS", "DHCP", "HTTP", "SMTP", "POP", "HTTPS", "TELNET", "GOPHER", "LDAP", "SNMP", "RDP", "IMAP", "NTP", "SMB", "MYSQL", "POSTGRESQL", "FTPS"]
        open_ports = scan_all_ports(url, protocols_to_scan)
        if open_ports:
            print(f"Open ports for {url}:")
            unique_ips = set()  # To store unique IP addresses
            for port_info in open_ports:
                port, protocol_name, service_name, service_version, banner = port_info
                print(f"Port {port} [{protocol_name}] is open: {service_name} {service_version} ({banner})")
                unique_ips.add(get_ip_address(url))
            print("Unique IP addresses:")
            for ip in unique_ips:
                print(ip)
    elif scan_all == "N":
        protocol = input("Enter the network protocol (FTP, SSH, DNS, DHCP, HTTP, SMTP, POP, HTTPS, TELNET, GOPHER, LDAP, SNMP, RDP, IMAP, NTP, SMB, MYSQL, POSTGRESQL, FTPS): ").strip().upper()
        if not validate_protocol(protocol):
            return
        scan_protocol_ports(url, protocol)
    else:
        print("Invalid choice. Exiting.")

def validate_protocol(protocol):
    valid_protocols = ["FTP", "SSH", "DNS", "DHCP", "HTTP", "SMTP", "POP", "HTTPS", "TELNET", "GOPHER", "LDAP", "SNMP", "RDP", "IMAP", "NTP", "SMB", "MYSQL", "POSTGRESQL", "FTPS", "TCP", "UDP"]
    if protocol not in valid_protocols:
        print("Invalid protocol.")
        return False
    return True

if __name__ == "__main__":
    main()
