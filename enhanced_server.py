#!/usr/bin/env python3
"""
Gelişmiş Server - IP Header Manipülasyonu ve Paket Analizi ile
"""

import socket
import threading
import time
import os
from scapy.all import *
from crypto_utils import generate_key, decrypt_file

class EnhancedServer:
    def __init__(self, host="127.0.0.1", port=65432, password="proje_sifresi_123"):
        self.host = host
        self.port = port
        self.password = password
        self.key = generate_key(password)
        self.received_packets = []
        self.packet_capture_active = False
        
    def start_packet_capture(self):
        """
        Arka planda paket yakalama başlatır
        """
        def capture_packets():
            print("[INFO] Paket yakalama başlatıldı...")
            self.packet_capture_active = True
            
            def packet_handler(packet):
                if not self.packet_capture_active:
                    return
                    
                if IP in packet and packet[IP].dst == self.host:
                    ip_layer = packet[IP]
                    
                    # Paket bilgilerini kaydet
                    packet_info = {
                        'timestamp': time.time(),
                        'src_ip': ip_layer.src,
                        'dst_ip': ip_layer.dst,
                        'ttl': ip_layer.ttl,
                        'flags': str(ip_layer.flags),
                        'id': ip_layer.id,
                        'checksum': ip_layer.chksum,
                        'size': len(packet)
                    }
                    
                    self.received_packets.append(packet_info)
                    
                    print(f"[PACKET] ID: {packet_info['id']}, TTL: {packet_info['ttl']}")
                    print(f"  Kaynak: {packet_info['src_ip']} -> Size: {packet_info['size']} bytes")
                    
                    # Checksum doğrulama
                    if self.verify_checksum(packet):
                        print("  ✓ Checksum doğru")
                    else:
                        print("  ✗ Checksum hatası!")
            
            try:
                # Paket yakala (filter ile sadece TCP paketleri)
                sniff(filter=f"tcp and dst host {self.host}", prn=packet_handler)
            except Exception as e:
                print(f"[ERROR] Paket yakalama hatası: {e}")
        
        # Paket yakalama thread'i başlat
        capture_thread = threading.Thread(target=capture_packets)
        capture_thread.daemon = True
        capture_thread.start()
    
    def verify_checksum(self, packet):
        """
        Paket checksum'ını doğrular
        """
        if IP in packet:
            original_checksum = packet[IP].chksum
            # Checksum'ı sıfırla ve yeniden hesapla
            packet[IP].chksum = 0
            new_packet = IP(raw(packet[IP]))
            return original_checksum == new_packet[IP].chksum
        return False
    
    def analyze_received_packets(self):
        """
        Alınan paketleri analiz eder
        """
        if not self.received_packets:
            print("[INFO] Analiz için paket bulunamadı.")
            return
        
        print("\n" + "="*60)
        print("PAKET ANALİZ RAPORU")
        print("="*60)
        
        total_packets = len(self.received_packets)
        total_size = sum(p['size'] for p in self.received_packets)
        
        print(f"Toplam Paket Sayısı: {total_packets}")
        print(f"Toplam Veri Boyutu: {total_size} bytes")
        print(f"Ortalama Paket Boyutu: {total_size/total_packets:.2f} bytes")
        
        # TTL analizi
        ttl_counts = {}
        for packet in self.received_packets:
            ttl = packet['ttl']
            ttl_counts[ttl] = ttl_counts.get(ttl, 0) + 1
        
        print(f"\nTTL Dağılımı:")
        for ttl, count in sorted(ttl_counts.items()):
            print(f"  TTL {ttl}: {count} paket")
        
        # Flags analizi
        flags_counts = {}
        for packet in self.received_packets:
            flags = packet['flags']
            flags_counts[flags] = flags_counts.get(flags, 0) + 1
        
        print(f"\nFlags Dağılımı:")
        for flags, count in flags_counts.items():
            print(f"  {flags}: {count} paket")
        
        # Zaman analizi
        if len(self.received_packets) > 1:
            first_time = self.received_packets[0]['timestamp']
            last_time = self.received_packets[-1]['timestamp']
            duration = last_time - first_time
            
            print(f"\nZaman Analizi:")
            print(f"  İlk paket: {time.ctime(first_time)}")
            print(f"  Son paket: {time.ctime(last_time)}")
            print(f"  Toplam süre: {duration:.2f} saniye")
            print(f"  Ortalama paket hızı: {total_packets/duration:.2f} paket/saniye")
        
        print("="*60)
    
    def start_traditional_server(self):
        """
        Geleneksel TCP server'ı başlatır
        """
        print(f"[INFO] Geleneksel TCP server başlatılıyor: {self.host}:{self.port}")
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen()
            
            print(f"[INFO] Server {self.host}:{self.port} adresinde dinleniyor...")
            
            while True:
                try:
                    conn, addr = s.accept()
                    print(f"[CONNECTION] {addr} bağlandı")
                    
                    # Dosyayı al
                    with open("alınan_şifreli.bin", "wb") as f:
                        while True:
                            data = conn.recv(4096)
                            if not data:
                                break
                            f.write(data)
                    
                    print("[INFO] Şifrelenmiş dosya alındı")
                    
                    # Şifreyi çöz
                    decrypt_file(self.key, "alınan_şifreli.bin", "çözülmüş_dosya.txt")
                    print("[SUCCESS] Dosya çözüldü ve kaydedildi: çözülmüş_dosya.txt")
                    
                    conn.close()
                    
                except KeyboardInterrupt:
                    print("\n[INFO] Server kapatılıyor...")
                    break
                except Exception as e:
                    print(f"[ERROR] Server hatası: {e}")
    
    def start_enhanced_server(self):
        """
        Gelişmiş server'ı başlatır (Paket yakalama + Geleneksel server)
        """
        print("=== GELİŞMİŞ GÜVENLI DOSYA TRANSFER SERVER ===")
        print("IP Header Manipülasyonu ve Paket Analizi ile\n")
        
        # Paket yakalamayı başlat
        self.start_packet_capture()
        
        # Kısa bekleme
        time.sleep(2)
        
        # Geleneksel server'ı başlat
        try:
            self.start_traditional_server()
        finally:
            # Paket yakalamayı durdur
            self.packet_capture_active = False
            time.sleep(1)
            
            # Analiz raporu oluştur
            self.analyze_received_packets()
    
    def send_custom_response(self, dest_ip, dest_port, message):
        """
        Özel IP header ile yanıt gönderir
        """
        print(f"[INFO] Özel yanıt gönderiliyor: {dest_ip}:{dest_port}")
        
        # Özel IP header ile paket oluştur
        ip_header = IP(
            dst=dest_ip,
            ttl=32,  # Düşük TTL (server yanıtı için)
            flags="DF",  # Don't Fragment
            id=99999  # Server yanıt ID'si
        )
        
        tcp_header = TCP(
            dport=dest_port,
            sport=self.port,
            flags="PA"  # Push + Ack
        )
        
        packet = ip_header / tcp_header / message
        
        try:
            send(packet, verbose=False)
            print("[SUCCESS] Özel yanıt gönderildi")
        except Exception as e:
            print(f"[ERROR] Yanıt gönderilirken hata: {e}")

def main():
    """
    Ana fonksiyon
    """
    try:
        server = EnhancedServer()
        server.start_enhanced_server()
    
    except KeyboardInterrupt:
        print("\n[INFO] Program kullanıcı tarafından sonlandırıldı.")
    except Exception as e:
        print(f"[ERROR] Program hatası: {e}")
        print("Not: Bu program yönetici yetkisi ile çalıştırılmalıdır!")

if __name__ == "__main__":
    main()


