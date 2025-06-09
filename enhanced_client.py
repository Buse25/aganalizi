#!/usr/bin/env python3
"""
Gelişmiş Client - IP Header Manipülasyonu ile Dosya Gönderimi
"""

import socket
import os
import time
import hashlib
from scapy.all import *
from crypto_utils import generate_key, encrypt_file

class EnhancedClient:
    def __init__(self, host="127.0.0.1", port=65432, password="proje_sifresi_123"):
        self.host = host
        self.port = port
        self.password = password
        self.key = generate_key(password)
        self.sent_packets = []
        
    def calculate_manual_checksum(self, data):
        """
        Manuel checksum hesaplama
        """
        checksum = 0
        # Veriyi 16-bit kelimeler halinde işle
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                word = (data[i] << 8) + data[i + 1]
            else:
                word = data[i] << 8
            checksum += word
            
        # Carry bitlerini ekle
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        
        # One's complement
        checksum = ~checksum & 0xFFFF
        return checksum
    
    def create_fragmented_packets(self, file_data, max_fragment_size=1400):
        """
        Dosyayı manuel parçalara böler ve özel IP header'ları oluşturur
        """
        packets = []
        total_fragments = (len(file_data) + max_fragment_size - 1) // max_fragment_size
        
        print(f"[INFO] Dosya {total_fragments} parçaya bölünüyor...")
        print(f"[INFO] Her parça max {max_fragment_size} byte")
        
        for i in range(total_fragments):
            start = i * max_fragment_size
            end = min((i + 1) * max_fragment_size, len(file_data))
            fragment_data = file_data[start:end]
            
            # Her parça için farklı IP özelikleri
            ttl_value = 64 - (i % 15)  # TTL değişkenliği (64'ten başlayıp azalıyor)
            packet_id = 50000 + i     # Her parça için benzersiz ID
            
            # Fragment flag'ları
            if i < total_fragments - 1:
                flags = "MF"  # More Fragments
            else:
                flags = 0     # Son parça
            
            # IP Header oluştur
            ip_header = IP(
                dst=self.host,
                ttl=ttl_value,
                flags=flags,
                frag=i * (max_fragment_size // 8),  # Fragment offset (8 byte biriminde)
                id=packet_id
            )
            
            # TCP Header oluştur
            tcp_header = TCP(
                dport=self.port,
                sport=RandShort(),  # Rastgele kaynak port
                seq=start,          # Sequence number olarak başlangıç pozisyonu
                flags="PA"          # Push + Ack
            )
            
            # Paketi birleştir
            packet = ip_header / tcp_header / fragment_data
            
            # Manuel checksum hesapla
            manual_checksum = self.calculate_manual_checksum(fragment_data)
            
            packet_info = {
                'packet': packet,
                'fragment_id': i,
                'size': len(fragment_data),
                'ttl': ttl_value,
                'packet_id': packet_id,
                'flags': str(flags),
                'manual_checksum': manual_checksum,
                'start_pos': start,
                'end_pos': end
            }
            
            packets.append(packet_info)
            
            print(f"  Parça {i+1}/{total_fragments}:")
            print(f"    Boyut: {len(fragment_data)} byte")
            print(f"    TTL: {ttl_value}")
            print(f"    ID: {packet_id}")
            print(f"    Flags: {flags}")
            print(f"    Manuel Checksum: {manual_checksum}")
        
        return packets
    
    def send_with_ip_manipulation(self, file_path, use_fragmentation=True):
        """
        IP manipülasyonu ile dosya gönderir
        """
        print(f"\n[INFO] IP manipülasyonu ile dosya gönderiliyor: {file_path}")
        
        # Dosyayı şifrele
        encrypted_file = "şifrelenmiş_dosya.bin"
        encrypt_file(self.key, file_path, encrypted_file)
        print(f"[INFO] Dosya şifrelendi: {encrypted_file}")
        
        # Şifrelenmiş dosyayı oku
        try:
            with open(encrypted_file, 'rb') as f:
                file_data = f.read()
            print(f"[INFO] Şifrelenmiş dosya boyutu: {len(file_data)} byte")
        except Exception as e:
            print(f"[ERROR] Şifrelenmiş dosya okunamadı: {e}")
            return False
        
        if use_fragmentation:
            # Parçalama ile gönder
            return self.send_fragmented(file_data)
        else:
            # Tek paket ile gönder
            return self.send_single_packet(file_data)
    
    def send_fragmented(self, file_data):
        """
        Parçalama ile gönderir
        """
        packets = self.create_fragmented_packets(file_data)
        
        print(f"\n[SEND] {len(packets)} parça gönderiliyor...")
        successful_sends = 0
        
        start_time = time.time()
        
        for i, packet_info in enumerate(packets):
            try:
                print(f"\n[SEND] Parça {i+1}/{len(packets)} gönderiliyor...")
                
                # Scapy ile gönder
                send(packet_info['packet'], verbose=False)
                
                # Başarılı gönderim bilgisini kaydet
                self.sent_packets.append({
                    'fragment_id': packet_info['fragment_id'],
                    'size': packet_info['size'],
                    'ttl': packet_info['ttl'],
                    'packet_id': packet_info['packet_id'],
                    'checksum': packet_info['manual_checksum'],
                    'timestamp': time.time()
                })
                
                successful_sends += 1
                print(f"  ✓ Parça {i+1} başarıyla gönderildi")
                
                # Ağ tıkanıklığını önlemek için kısa bekleme
                time.sleep(0.05)
                
            except Exception as e:
                print(f"  ✗ Parça {i+1} gönderilemedi: {e}")
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"\n[RESULT] {successful_sends}/{len(packets)} parça başarıyla gönderildi")
        print(f"[TIMING] Toplam süre: {duration:.2f} saniye")
        print(f"[SPEED] Ortalama hız: {len(file_data)/duration:.2f} byte/saniye")
        
        return successful_sends == len(packets)
    
    def send_single_packet(self, file_data):
        """
        Tek paket ile gönderir (Özel IP header ile)
        """
        print("[SEND] Tek paket ile gönderiliyor...")
        
        # Özel IP header
        ip_header = IP(
            dst=self.host,
            ttl=128,        # Yüksek TTL
            flags="DF",     # Don't Fragment
            id=12345       # Özel ID
        )
        
        tcp_header = TCP(
            dport=self.port,
            sport=8888,
            flags="PA"
        )
        
        packet = ip_header / tcp_header / file_data
        
        try:
            send(packet, verbose=False)
            print("[SUCCESS] Tek paket başarıyla gönderildi")
            return True
        except Exception as e:
            print(f"[ERROR] Paket gönderilemedi: {e}")
            return False
    
    def send_traditional(self, file_path):
        """
        Geleneksel TCP ile gönderir (Karşılaştırma için)
        """
        print(f"\n[INFO] Geleneksel TCP ile gönderiliyor: {file_path}")
        
        # Dosyayı şifrele
        encrypted_file = "şifrelenmiş_dosya.bin"
        encrypt_file(self.key, file_path, encrypted_file)
        
        start_time = time.time()
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.host, self.port))
                
                # 🔐 Kimlik bilgilerini gönder
                kullanici_adi = "halime"
                sifre = "12345"
                kimlik_bilgisi = f"{kullanici_adi}:{sifre}"
                s.send(kimlik_bilgisi.encode())  # Şifreyi gönder
                
                # 🔄 Sonra dosyayı gönder
                with open(encrypted_file, "rb") as f:
                    file_data = f.read()
                    s.sendall(file_data)

                
 
                with open(encrypted_file, "rb") as f:
                    file_data = f.read()
                    s.sendall(file_data)
                
                print("[SUCCESS] Geleneksel TCP ile gönderildi")
                
        except Exception as e:
            print(f"[ERROR] Geleneksel gönderim hatası: {e}")
            return False
        
        end_time = time.time()
        duration = end_time - start_time
        
        with open(encrypted_file, "rb") as f:
            file_size = len(f.read())
        
        print(f"[TIMING] Geleneksel süre: {duration:.2f} saniye")
        print(f"[SPEED] Geleneksel hız: {file_size/duration:.2f} byte/saniye")
        
        return True
    
    def generate_client_report(self):
        """
        İstemci tarafında performans raporu oluşturur
        """
        if not self.sent_packets:
            print("[WARNING] Rapor için paket bilgisi yok!")
            return
        
        print("\n" + "="*60)
        print("İSTEMCİ PERFORMANS RAPORU")
        print("="*60)
        
        total_packets = len(self.sent_packets)
        total_size = sum(p['size'] for p in self.sent_packets)
        
        print(f"Gönderilen Paket Sayısı: {total_packets}")
        print(f"Toplam Veri Boyutu: {total_size} bytes")
        print(f"Ortalama Paket Boyutu: {total_size/total_packets:.2f} bytes")
        
        # TTL dağılımı
        ttl_counts = {}
        for packet in self.sent_packets:
            ttl = packet['ttl']
            ttl_counts[ttl] = ttl_counts.get(ttl, 0) + 1
        
        print(f"\nGönderilen TTL Dağılımı:")
        for ttl, count in sorted(ttl_counts.items()):
            print(f"  TTL {ttl}: {count} paket")
        
        print("="*60)

def main():
    """
    Ana fonksiyon - Kullanım örnekleri
    """
    print("=== GELİŞMİŞ GÜVENLI DOSYA TRANSFER CLIENT ===")
    print("IP Header Manipülasyonu ile\n")
    
    client = EnhancedClient()
    
    # Test dosyası oluştur
    test_file = "gönderilecek_dosya.txt"
    test_content = "Bu dosya IP header manipülasyonu ile gönderilecek!\n" * 50
    
    try:
        with open(test_file, 'w', encoding='utf-8') as f:
            f.write(test_content)
        print(f"[INFO] Test dosyası oluşturuldu: {test_file}")
    except Exception as e:
        print(f"[ERROR] Test dosyası oluşturulamadı: {e}")
        return
    
    # Menü
    while True:
        print("\n" + "="*50)
        print("GÖNDERIM SEÇENEKLERİ")
        print("="*50)
        print("1. IP Manipülasyonu ile Parçalama (Önerilen)")
        print("2. IP Manipülasyonu ile Tek Paket")
        print("3. Geleneksel TCP (Karşılaştırma)")
        print("4. Performans Raporu")
        print("5. Çıkış")
        print("="*50)
        
        choice = input("Seçiminiz (1-5): ").strip()
        
        if choice == "1":
            success = client.send_with_ip_manipulation(test_file, use_fragmentation=True)
            if success:
                client.generate_client_report()
        
        elif choice == "2":
            success = client.send_with_ip_manipulation(test_file, use_fragmentation=False)
        
        elif choice == "3":
            client.send_traditional(test_file)
        
        elif choice == "4":
            client.generate_client_report()
        
        elif choice == "5":
            print("[INFO] Program sonlandırılıyor...")
            break
        
        else:
            print("[ERROR] Geçersiz seçim!")
    
    # Temizlik
    try:
        os.remove(test_file)
        if os.path.exists("şifrelenmiş_dosya.bin"):
            os.remove("şifrelenmiş_dosya.bin")
    except:
        pass

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] Program kullanıcı tarafından sonlandırıldı.")
    except Exception as e:
        print(f"[ERROR] Program hatası: {e}")
        print("Not: Bu program yönetici yetkisi ile çalıştırılmalıdır!")


