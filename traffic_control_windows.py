import scapy.all as scapy
import threading
import time
from queue import PriorityQueue

# Trafik verilerini analiz eden ve önceliklendirme yapan bir yapı
class TrafficController:
    def __init__(self):
        self.packet_queue = PriorityQueue()
        self.running = True

    def capture_packets(self):
        print("[+] Paket dinleniyor... (Ctrl+C ile durdur)")
        scapy.sniff(prn=self.analyze_packet, store=False)

    def analyze_packet(self, packet):
        priority = self.get_priority(packet)
        self.packet_queue.put((priority, time.time(), packet))

    def get_priority(self, packet):
        # Örnek: DNS, HTTP, ICMP gibi protokollere göre öncelik belirle
        if packet.haslayer(scapy.DNS):
            return 1  # yüksek öncelik
        elif packet.haslayer(scapy.TCP):
            return 2
        elif packet.haslayer(scapy.UDP):
            return 3
        else:
            return 5  # düşük öncelik

    def process_packets(self):
        while self.running:
            if not self.packet_queue.empty():
                _, _, packet = self.packet_queue.get()
                self.handle_packet(packet)
            else:
                time.sleep(0.1)

    def handle_packet(self, packet):
        print(f"\n--- Paket İşlendi ---")
        print(packet.summary())
        time.sleep(0.5)  # Gecikme simülasyonu (QoS etkisi gibi)

    def stop(self):
        self.running = False

if __name__ == "__main__":
    controller = TrafficController()

    try:
        thread = threading.Thread(target=controller.process_packets)
        thread.start()
        controller.capture_packets()
    except KeyboardInterrupt:
        print("\n[-] Trafik kontrolü durduruluyor...")
        controller.stop()
        thread.join()
