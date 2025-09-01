#!/usr/bin/env python3
"""
IoT Device Web Interface Analyzer
Simple analyzer for IoT devices found by zmap
Usage: zmap -p 80 -B 10M | python3 new.py
"""

import requests
import sys
import json
import re
import os
import shutil
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import warnings

# Disable SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class IoTAnalyzer:
    def __init__(self):
        self.results_file = f"devices_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self.stats = {
            'total_scanned': 0,
            'devices_found': 0,
            'by_vendor': {},
            'by_type': {},
            'start_time': datetime.now().isoformat()
        }
        
        # Setup output directories
        self.setup_directories()
        
        # Device vendors and their patterns (x86 focused)
        self.vendors = {
            'TP-Link': ['tp-link', 'tplinkwifi', 'archer', 'tl-wr', 'tl-wa', 'tl-', 'tp_link'],
            'Netgear': ['netgear', 'readynas', 'nighthawk', 'orbi', 'prosafe', 'netgear inc'],
            'D-Link': ['d-link', 'dlink', 'dir-', 'dap-', 'dgs-', 'des-', 'dwl-'],
            'ASUS': ['asus', 'rt-', 'ac68u', 'ac86u', 'zenwifi', 'asuswrt', 'asustek'],
            'Linksys': ['linksys', 'wrt', 'ea6350', 'velop', 'cisco linksys'],
            'Cisco': ['cisco', 'rv340', 'meraki', 'catalyst', 'aironet', 'cisco systems'],
            'Zyxel': ['zyxel', 'zywall', 'usg', 'nebula', 'zyxel communications'],
            'Huawei': ['huawei', 'honor', 'hg8145', 'huawei technologies'],
            'Xiaomi': ['xiaomi', 'mi router', 'miwifi', 'redmi'],
            'Ubiquiti': ['ubiquiti', 'unifi', 'edgerouter', 'ubnt', 'edgemax'],
            'Mikrotik': ['mikrotik', 'routeros', 'routerboard'],
            'Tenda': ['tenda', 'ac15', 'tenda technology'],
            'Buffalo': ['buffalo', 'wzr-', 'whr-', 'terastation'],
            'Belkin': ['belkin', 'f5d', 'f7d', 'f9k'],
            'Motorola': ['motorola', 'surfboard', 'arris'],
            'Alcatel': ['alcatel', 'alcatel-lucent'],
            'ZTE': ['zte', 'zxhn'],
            'Technicolor': ['technicolor', 'thomson'],
            'AVM': ['avm', 'fritz', 'fritzbox'],
            'Intel': ['intel', 'intel corporation', 'x86', 'pentium', 'core i'],
            'AMD': ['amd', 'athlon', 'ryzen', 'epyc'],
            'Dell': ['dell', 'dell inc', 'poweredge', 'optiplex'],
            'HP': ['hp', 'hewlett-packard', 'compaq', 'proliant'],
            'Lenovo': ['lenovo', 'thinkpad', 'thinkcentre'],
            'IBM': ['ibm', 'international business machines'],
            'Supermicro': ['supermicro', 'super micro'],
            'MSI': ['msi', 'micro-star'],
            'Gigabyte': ['gigabyte', 'aorus'],
            'ASRock': ['asrock'],
            'Synology': ['synology', 'diskstation', 'rackstation'],
            'QNAP': ['qnap', 'turbo nas'],
            'Drobo': ['drobo'],
            'WD': ['western digital', 'wd my cloud', 'mycloud'],
            'Seagate': ['seagate'],
            'Hikvision': ['hikvision', 'hik-connect'],
            'Dahua': ['dahua', 'dahua technology'],
            'Axis': ['axis', 'axis communications'],
            'Bosch': ['bosch', 'bosch security'],
            'Panasonic': ['panasonic', 'panasonic system'],
            'Samsung': ['samsung', 'samsung techwin'],
            'LG': ['lg', 'lg electronics'],
            'Sony': ['sony', 'sony corporation'],
            'Vivotek': ['vivotek'],
            'Foscam': ['foscam'],
            'Reolink': ['reolink'],
            'Canon': ['canon', 'canon inc'],
            'Epson': ['epson', 'seiko epson'],
            'Brother': ['brother', 'brother industries'],
            'Xerox': ['xerox', 'xerox corporation'],
            'Ricoh': ['ricoh', 'ricoh company'],
            'Lexmark': ['lexmark'],
            'Kyocera': ['kyocera'],
            'Sharp': ['sharp', 'sharp corporation'],
            'Konica': ['konica', 'konica minolta'],
            'Fortinet': ['fortinet', 'fortigate'],
            'SonicWall': ['sonicwall', 'sonicwall inc'],
            'Watchguard': ['watchguard'],
            'Palo Alto': ['palo alto', 'palo alto networks'],
            'Checkpoint': ['checkpoint', 'check point'],
            'Juniper': ['juniper', 'juniper networks'],
            'F5': ['f5 networks', 'f5-bigip'],
            'Barracuda': ['barracuda'],
            'Sophos': ['sophos'],
            'Cyberoam': ['cyberoam'],
            'pfSense': ['pfsense', 'netgate'],
            'OPNsense': ['opnsense'],
            'Untangle': ['untangle'],
            'Smoothwall': ['smoothwall'],
            'IPFire': ['ipfire'],
            'ClearOS': ['clearos'],
            'Endian': ['endian'],
            'Astaro': ['astaro'],
            'Kerio': ['kerio'],
            'Applian': ['applian'],
            'Microsoft': ['microsoft', 'windows', 'iis', 'exchange'],
            'VMware': ['vmware', 'vsphere', 'vcenter'],
            'Citrix': ['citrix', 'xenserver'],
            'Oracle': ['oracle', 'sun microsystems'],
            'RedHat': ['red hat', 'rhel', 'centos'],
            'SUSE': ['suse', 'opensuse'],
            'Debian': ['debian'],
            'Ubuntu': ['ubuntu', 'canonical'],
            'Apache': ['apache'],
            'Nginx': ['nginx'],
            'Lighttpd': ['lighttpd'],
            'Cherokee': ['cherokee'],
            'Caddy': ['caddy'],
            'Traefik': ['traefik']
        }
        
        # Device types (x86 focused)
        self.device_types = {
            'Router': ['router', 'gateway', 'wireless', 'wifi', 'access point', 'ap', 'wlan', 'bridge', 'repeater', 'extender'],
            'Camera': ['camera', 'webcam', 'ipcam', 'surveillance', 'cctv', 'video', 'nvr', 'dvr', 'cam', 'vision'],
            'NAS': ['nas', 'storage', 'diskstation', 'rackstation', 'terastation', 'linkstation', 'my cloud', 'network storage'],
            'Printer': ['printer', 'print server', 'cups', 'printing', 'multifunction', 'mfp', 'scanner', 'copier'],
            'Switch': ['switch', 'managed switch', 'ethernet switch', 'network switch', 'layer 2', 'layer 3'],
            'Modem': ['modem', 'dsl', 'cable modem', 'docsis', 'adsl', 'vdsl'],
            'Server': ['server', 'web server', 'file server', 'mail server', 'database', 'application server', 'dedicated', 'blade'],
            'Firewall': ['firewall', 'security appliance', 'utm', 'next generation', 'threat protection', 'intrusion'],
            'VPN': ['vpn', 'virtual private network', 'ssl vpn', 'ipsec', 'remote access'],
            'Load Balancer': ['load balancer', 'load balancing', 'application delivery', 'adc', 'big-ip'],
            'Management': ['management', 'administration', 'console', 'control panel', 'web interface', 'config'],
            'Media Server': ['media server', 'streaming', 'plex', 'emby', 'jellyfin', 'dlna', 'upnp'],
            'Backup': ['backup', 'backup server', 'recovery', 'archive', 'vault'],
            'Monitor': ['monitor', 'monitoring', 'snmp', 'nagios', 'zabbix', 'cacti'],
            'Virtualization': ['virtualization', 'hypervisor', 'vm', 'virtual machine', 'vmware', 'hyper-v', 'xen'],
            'Industrial PC': ['industrial', 'embedded', 'automation', 'scada', 'hmi', 'plc'],
            'Terminal Server': ['terminal server', 'remote desktop', 'citrix', 'rdp', 'vnc'],
            'Proxy': ['proxy', 'proxy server', 'squid', 'forward proxy', 'reverse proxy'],
            'Mail Server': ['mail server', 'email', 'smtp', 'pop3', 'imap', 'exchange', 'postfix'],
            'DNS Server': ['dns server', 'domain name', 'bind', 'powerdns', 'dnsmasq'],
            'DHCP Server': ['dhcp server', 'dhcp', 'ip assignment', 'address pool'],
            'Time Server': ['time server', 'ntp', 'network time protocol', 'chrony'],
            'Database': ['database', 'mysql', 'postgresql', 'mssql', 'oracle', 'mongodb'],
            'Web Application': ['web application', 'webapp', 'portal', 'dashboard', 'admin panel'],
            'Game Server': ['game server', 'gaming', 'minecraft', 'counter-strike', 'teamspeak'],
            'Chat Server': ['chat server', 'irc', 'xmpp', 'jabber', 'matrix'],
            'File Share': ['file share', 'smb', 'cifs', 'nfs', 'ftp', 'sftp'],
            'Version Control': ['version control', 'git', 'svn', 'mercurial', 'gitlab', 'github'],
            'CI/CD': ['continuous integration', 'jenkins', 'bamboo', 'teamcity', 'gitlab ci'],
            'Container': ['container', 'docker', 'kubernetes', 'k8s', 'openshift'],
            'Cloud': ['cloud', 'aws', 'azure', 'gcp', 'openstack', 'cloudstack']
        }
        
        # x86 architecture indicators
        self.x86_indicators = [
            'x86', 'x64', 'x86_64', 'i386', 'i486', 'i586', 'i686',
            'intel', 'amd', 'pentium', 'celeron', 'atom', 'core',
            'athlon', 'ryzen', 'epyc', 'xeon', 'opteron',
            'windows', 'linux', 'ubuntu', 'debian', 'centos', 'rhel',
            'pc', 'desktop', 'workstation', 'server'
        ]
        
        # Non-x86 architecture indicators to filter out
        self.non_x86_indicators = [
            'arm', 'mips', 'powerpc', 'sparc', 'risc-v',
            'armv7', 'armv8', 'aarch64', 'cortex',
            'broadcom', 'qualcomm', 'mediatek', 'allwinner',
            'rockchip', 'amlogic', 'realtek rtl'
        ]

    def setup_directories(self):
        """Setup output directories"""
        # Remove old directories if they exist
        if os.path.exists('by_vendor'):
            shutil.rmtree('by_vendor')
        if os.path.exists('by_type'):
            shutil.rmtree('by_type')
        
        # Create new directories
        os.makedirs('by_vendor', exist_ok=True)
        os.makedirs('by_type', exist_ok=True)

    def get_web_info(self, ip, port=80):
        """Get web interface information"""
        try:
            # Try HTTP first
            url = f"http://{ip}:{port}/"
            response = requests.get(
                url, 
                timeout=5, 
                allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; IoT Scanner)'}
            )
            
            return {
                'url': url,
                'status': response.status_code,
                'title': self.extract_title(response.text),
                'server': response.headers.get('Server', ''),
                'content': response.text[:1000].lower()
            }
        except:
            # Try HTTPS if HTTP fails
            try:
                url = f"https://{ip}:{port}/"
                response = requests.get(
                    url, 
                    timeout=5, 
                    verify=False,
                    allow_redirects=True,
                    headers={'User-Agent': 'Mozilla/5.0 (compatible; IoT Scanner)'}
                )
                
                return {
                    'url': url,
                    'status': response.status_code,
                    'title': self.extract_title(response.text),
                    'server': response.headers.get('Server', ''),
                    'content': response.text[:1000].lower()
                }
            except:
                return None

    def extract_title(self, html):
        """Extract page title"""
        try:
            match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
            return match.group(1).strip() if match else ""
        except:
            return ""

    def identify_vendor(self, info):
        """Identify device vendor"""
        search_text = f"{info.get('title', '')} {info.get('server', '')} {info.get('content', '')}".lower()
        
        for vendor, patterns in self.vendors.items():
            for pattern in patterns:
                if pattern.lower() in search_text:
                    return vendor
        return "Unknown"

    def identify_device_type(self, info):
        """Identify device type"""
        search_text = f"{info.get('title', '')} {info.get('content', '')}".lower()
        
        for device_type, patterns in self.device_types.items():
            for pattern in patterns:
                if pattern.lower() in search_text:
                    return device_type
        return "Unknown"

    def is_x86_device(self, info):
        """Check if device is x86 architecture"""
        search_text = f"{info.get('title', '')} {info.get('server', '')} {info.get('content', '')}".lower()
        
        # Check for non-x86 indicators first (filter out)
        for indicator in self.non_x86_indicators:
            if indicator.lower() in search_text:
                return False
        
        # Check for x86 indicators
        for indicator in self.x86_indicators:
            if indicator.lower() in search_text:
                return True
        
        # If no clear architecture indicators, assume it could be x86
        # (many devices don't explicitly mention architecture)
        return True

    def analyze_ip(self, ip_line):
        """Analyze single IP address"""
        ip = ip_line.strip()
        if not ip:
            return
        
        self.stats['total_scanned'] += 1
        
        # Get web interface info
        web_info = self.get_web_info(ip)
        if not web_info:
            return
        
        # Filter for x86 architecture only
        if not self.is_x86_device(web_info):
            return
        
        # Identify device
        vendor = self.identify_vendor(web_info)
        device_type = self.identify_device_type(web_info)
        
        device = {
            'ip': ip,
            'vendor': vendor,
            'type': device_type,
            'title': web_info.get('title', ''),
            'server': web_info.get('server', ''),
            'url': web_info.get('url', ''),
            'status': web_info.get('status', 0),
            'timestamp': datetime.now().isoformat()
        }
        
        # Update statistics
        self.stats['devices_found'] += 1
        self.stats['by_vendor'][vendor] = self.stats['by_vendor'].get(vendor, 0) + 1
        self.stats['by_type'][device_type] = self.stats['by_type'].get(device_type, 0) + 1
        
        # Save IP to files immediately
        self.save_ip_to_files(ip, vendor, device_type)
        
        # Save device info
        self.save_device(device)
        
        # Print result
        print(f"[+] {ip} - {device_type} ({vendor}) - {web_info.get('title', 'No title')}")

    def save_device(self, device):
        """Save device to results file"""
        try:
            # Try to read existing data
            try:
                with open(self.results_file, 'r') as f:
                    data = json.load(f)
            except:
                data = {'devices': [], 'statistics': {}}
            
            # Add new device
            data['devices'].append(device)
            data['statistics'] = self.stats
            
            # Write back
            with open(self.results_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            pass

    def save_ip_to_files(self, ip, vendor, device_type):
        """Save IP to files immediately"""
        # Save to vendor file
        try:
            clean_vendor = re.sub(r'[^\w\-_]', '_', vendor)
            vendor_file = f"by_vendor/{clean_vendor}.txt"
            
            # Check if IP already exists in file to avoid duplicates
            existing_ips = set()
            if os.path.exists(vendor_file):
                try:
                    with open(vendor_file, 'r') as f:
                        existing_ips = set(line.strip() for line in f if line.strip())
                except:
                    pass
            
            if ip not in existing_ips:
                with open(vendor_file, 'a') as f:
                    f.write(f"{ip}\n")
        except:
            pass
        
        # Save to type file
        try:
            clean_type = re.sub(r'[^\w\-_]', '_', device_type)
            type_file = f"by_type/{clean_type}.txt"
            
            # Check if IP already exists in file to avoid duplicates
            existing_ips = set()
            if os.path.exists(type_file):
                try:
                    with open(type_file, 'r') as f:
                        existing_ips = set(line.strip() for line in f if line.strip())
                except:
                    pass
            
            if ip not in existing_ips:
                with open(type_file, 'a') as f:
                    f.write(f"{ip}\n")
        except:
            pass

    def print_stats(self):
        """Print final statistics"""
        print(f"\n[*] Scan completed")
        print(f"[*] Total scanned: {self.stats['total_scanned']}")
        print(f"[*] Devices found: {self.stats['devices_found']}")
        print(f"[*] Results saved to: {self.results_file}")
        
        if self.stats['by_vendor']:
            print(f"\n[*] Top vendors:")
            for vendor, count in sorted(self.stats['by_vendor'].items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"    {vendor}: {count}")
        
        if self.stats['by_type']:
            print(f"\n[*] Device types:")
            for dev_type, count in sorted(self.stats['by_type'].items(), key=lambda x: x[1], reverse=True):
                print(f"    {dev_type}: {count}")
        
        print(f"\n[*] IP files continuously saved to by_vendor/ and by_type/ directories")

def main():
    print("[*] x86 IoT Device Web Interface Analyzer")
    print("[*] Focused on x86 architecture devices only")
    print("[*] Reading IPs from stdin (use with zmap)...")
    print("[*] Example: zmap -p 80 -B 10M | python3 new.py")
    print()
    
    analyzer = IoTAnalyzer()
    
    with ThreadPoolExecutor(max_workers=300) as executor:
        try:
            for line in sys.stdin:
                line = line.strip()
                if line:
                    executor.submit(analyzer.analyze_ip, line)
        except KeyboardInterrupt:
            print("\n[*] Scan interrupted by user")
    
    analyzer.print_stats()

if __name__ == "__main__":
    main()