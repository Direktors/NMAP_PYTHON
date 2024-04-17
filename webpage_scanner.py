import re
import socket
import random
import time
import requests
import subprocess
import whois
import ftplib

def get_url():
    url = input("Enter the webpage URL you want to scan: ").strip()
    return url

def validate_url(url):
    url_pattern = re.compile(
        r'^(?:http|https)://'
        r'(?:[\w-]+\.)*[\w-]+'
        r'(?:\:\d+)?'
        r'(?:\/\S*)?$'
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
    USER_AGENT_STRINGS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.9999.999 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0",
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.9999.999 Safari/537.36 OPR/99.0.9999.999",
    ]
    return random.choice(USER_AGENT_STRINGS)

def get_whois_info(ip_address):
    try:
        domain = whois.whois(ip_address)
        return str(domain)
    except Exception as e:
        return f"Error performing WHOIS lookup: {e}"

def get_banner_ftps(host, port):
    try:
        ftp = ftplib.FTP_TLS()
        ftp.connect(host, port)
        ftp.login()
        banner = ftp.getwelcome()
        ftp.quit()
        return banner
    except Exception as e:
        print(f"Failed to retrieve banner for port {port}: {e}")
        return None

def scan_all_ports(url, protocols):
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
        
        try:
            reverse_dns = socket.gethostbyaddr(ip_address)[0]
            print(f"Reverse DNS Lookup: {reverse_dns}")
        except socket.herror:
            print("Reverse DNS Lookup: Not found")
        except Exception as e:
            print(f"Error performing Reverse DNS Lookup: {e}")

        whois_info = get_whois_info(ip_address)
        print("WHOIS Lookup:")
        print(whois_info)

    print(f"Scanning ports for {url} using automatic mode:")
    
    open_ports = []
    for protocol in protocols:
        ports = get_ports_for_protocol(protocol)
        
        for p in ports:
            s = None  # Define s here
            
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)

                headers = {"User-Agent": get_random_user_agent()}

                s.connect((host, p))
                print(f"Port {p} [{protocol}] is open on {host}")
                
                try:
                    if protocol == "FTPS":
                        banner = get_banner_ftps(host, p)
                        if banner is not None:
                            service_info = parse_banner(banner)
                            open_ports.append((p, protocol) + service_info)
                        else:
                            print(f"Failed to retrieve banner for port {p}.")
                    else:
                        banner = s.recv(4096).decode('utf-8')
                        service_info = parse_banner(banner)
                        open_ports.append((p, protocol) + service_info)
                except ConnectionResetError:
                    print(f"Failed to retrieve banner for port {p}.")
            except (socket.timeout, ConnectionRefusedError):
                pass
            except socket.gaierror:
                print("Error resolving host.")
            finally:
                if s:
                    s.close()
                
            delay = random.uniform(0.5, 2.0)
            time.sleep(delay)
    
    return open_ports



def parse_banner(banner):
    service_name = "Unknown"
    service_version = "Unknown"
    
    if banner:
        if "SSH" in banner:
            service_name = "SSH"
            match = re.search(r'SSH-(\S+)', banner)
            if match:
                service_version = match.group(1)
        elif "FTP" in banner:
            service_name = "FTP"
            # Add regex pattern to extract FTP server version from banner
        elif "HTTP" in banner:
            service_name = "HTTP"
            # Add regex pattern to extract HTTP server version from banner
        elif "SMTP" in banner:
            service_name = "SMTP"
            # Add regex pattern to extract SMTP server version from banner
        elif "POP" in banner:
            service_name = "POP"
            # Add regex pattern to extract POP server version from banner
        elif "HTTPS" in banner:
            service_name = "HTTPS"
            # Add regex pattern to extract HTTPS server version from banner
        elif "TELNET" in banner:
            service_name = "TELNET"
            # Add regex pattern to extract TELNET server version from banner
        elif "IMAP" in banner:
            service_name = "IMAP"
            # Add regex pattern to extract IMAP server version from banner
        elif "LDAP" in banner:
            service_name = "LDAP"
            # Add regex pattern to extract LDAP server version from banner
        elif "SNMP" in banner:
            service_name = "SNMP"
            # Add regex pattern to extract SNMP server version from banner
        elif "RDP" in banner:
            service_name = "RDP"
            # Add regex pattern to extract RDP server version from banner
        elif "NTP" in banner:
            service_name = "NTP"
            # Add regex pattern to extract NTP server version from banner
        elif "SMB" in banner:
            service_name = "SMB"
            # Add regex pattern to extract SMB server version from banner
        elif "MYSQL" in banner:
            service_name = "MYSQL"
            # Add regex pattern to extract MYSQL server version from banner
        elif "POSTGRESQL" in banner:
            service_name = "POSTGRESQL"
            # Add regex pattern to extract POSTGRESQL server version from banner
        elif "FTPS" in banner:
            service_name = "FTPS"
            # Add regex pattern to extract FTPS server version from banner
        elif "UDP" in banner:
            service_name = "UDP"
            # Add regex pattern to extract UDP server version from banner
        elif "TCP" in banner:
            service_name = "TCP"
            # Add regex pattern to extract TCP server version from banner
    # Add more conditions to handle other services like DHCP, DNS, etc.
    
    return service_name, service_version, banner.strip()



def get_ports_for_protocol(protocol):
    protocol_ports = {
        "FTP": [21, 2121],
        "SSH": [22],
        "DNS": [53],
        "DHCP": [67, 68],
        "HTTP": [80, 8080],
        "SMTP": [25],
        "POP": [110],
        "HTTPS": [443, 8443],
        "TELNET": [23],
        "GOPHER": [70],
        "IP": [],  # Add IP to manual mode
        "LDAP": [389],
        "SNMP": [161],
        "RDP": [3389],
        "IMAP": [143],
        "NTP": [123],
        "SMB": [445],
        "MYSQL": [3306],
        "POSTGRESQL": [5432],
        "FTPS": [990, 2121],
        "TCP": list(range(1, 1024)),  # Add TCP to manual mode
        "UDP": list(range(1, 1024)),  # Add UDP to manual mode
    }
    return protocol_ports.get(protocol, [])

def scan_protocol_ports(url, protocol):
    port_range = get_port_range(protocol)
    if port_range is None:
        return
    
    print(f"Enter starting port number for {protocol} [{port_range}]: ", end="")
    start_port = int(input())
    print(f"Enter ending port number for {protocol}: ", end="")
    end_port = int(input())
    
    if start_port < port_range[0] or end_port > port_range[1] or end_port < start_port:
        print(f"Invalid port range. Port range for {protocol}: {port_range[0]}-{port_range[1]}")
        return
    
    print(f"Scanning ports for {url} using manual mode for protocol {protocol}:")
    ports_to_scan = list(range(start_port, end_port + 1))
    open_ports = []
    host = re.search(r'(?<=://)(.*?)(?=/|$)', url).group(1)
    for port in ports_to_scan:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)

        try:
            s.connect((host, port))
            print(f"Port {port} [{protocol}] is open on {host}")
            try:
                banner = s.recv(4096).decode('utf-8')
                service_info = parse_banner(banner)
                open_ports.append((port, protocol) + service_info)
            except ConnectionResetError:
                print(f"Failed to retrieve banner for port {port}.")
        except (socket.timeout, ConnectionRefusedError):
            pass
        except socket.gaierror:
            print("Error resolving host.")
        finally:
            s.close()
                
        delay = random.uniform(0.5, 2.0)
        time.sleep(delay)

    if open_ports:
        print(f"Open ports for {url} using manual mode for protocol {protocol}:")
        for port_info in open_ports:
            port, protocol_name, service_name, service_version, banner = port_info
            print(f"Port {port} [{protocol_name}] is open: {service_name} {service_version} ({banner})")

def get_port_range(protocol):
    port_ranges = {
        "FTP": (21, 2121),
        "SSH": (22, 22),
        "DNS": (53, 53),
        "DHCP": (67, 68),
        "HTTP": (80, 8080),
        "SMTP": (25, 25),
        "POP": (110, 110),
        "HTTPS": (443, 8443),
        "TELNET": (23, 23),
        "GOPHER": (70, 70),
        "IP": (0, 65535),  # Entire port range for IP
        "LDAP": (389, 389),
        "SNMP": (161, 161),
        "RDP": (3389, 3389),
        "IMAP": (143, 143),
        "NTP": (123, 123),
        "SMB": (445, 445),
        "MYSQL": (3306, 3306),
        "POSTGRESQL": (5432, 5432),
        "FTPS": (990, 2121),
        "TCP": (1, 1023),  # Well-known TCP ports
        "UDP": (1, 1023),  # Well-known UDP ports
    }
    return port_ranges.get(protocol)

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
            unique_ips = set()
            for port_info in open_ports:
                port, protocol_name, service_name, service_version, banner = port_info
                print(f"Port {port} [{protocol_name}] is open: {service_name} {service_version} ({banner})")
                unique_ips.add(get_ip_address(url))
            print("Unique IP addresses:")
            for ip in unique_ips:
                print(ip)
    elif scan_all == "N":
        protocol = input("Enter the network protocol (FTP, SSH, DNS, DHCP, HTTP, SMTP, POP, HTTPS, TELNET, GOPHER, LDAP, SNMP, RDP, IMAP, NTP, SMB, MYSQL, POSTGRESQL, FTPS, TCP, UDP, IP): ").strip().upper()
        if not validate_protocol(protocol):
            return
        scan_protocol_ports(url, protocol)
    else:
        print("Invalid choice. Exiting.")

def validate_protocol(protocol):
    valid_protocols = ["FTP", "SSH", "DNS", "DHCP", "HTTP", "SMTP", "POP", "HTTPS", "TELNET", "GOPHER", "LDAP", "SNMP", "RDP", "IMAP", "NTP", "SMB", "MYSQL", "POSTGRESQL", "FTPS", "TCP", "UDP", "IP"]
    if protocol not in valid_protocols:
        print("Invalid protocol.")
        return False
    return True

if __name__ == "__main__":
    main()
