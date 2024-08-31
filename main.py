import psutil
from scapy.all import sniff, IP, TCP, conf

TARGET_PROCESS = "java.exe"

def find_java_pid(process_name):
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == process_name:
            return proc.info['pid']
    return None

def packet_callback(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"送信先IP: {dst_ip}")

def monitor_traffic(pid):
    proc = psutil.Process(pid)
    connections = proc.net_connections(kind='inet')
    if not connections:
        print("接続が見つかりません。")
        return

    local_ports = [conn.laddr.port for conn in connections]
    print(f"監視するポート: {local_ports}")

    conf.L3socket

    sniff(filter=f"tcp port ({' or '.join(map(str, local_ports))})", prn=packet_callback, store=0)

if __name__ == "__main__":
    java_pid = find_java_pid(TARGET_PROCESS)
    if java_pid:
        print(f"{TARGET_PROCESS} のPID: {java_pid}")
        monitor_traffic(java_pid)
    else:
        print(f"{TARGET_PROCESS} のプロセスが見つかりません。")