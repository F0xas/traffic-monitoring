import os
from scapy.all import sniff, IP, TCP, UDP, ARP, Raw

# Создаем папку для логов (если её нет)
log_dir = "logs"
os.makedirs(log_dir, exist_ok=True)

# Функция записи в файл
def write_to_file(filename, data):
    filepath = os.path.join(log_dir, filename)  # Формируем путь к файлу
    with open(filepath, "a") as f:
        f.write(data + "\n")
    print(f"Записано в файл: {filepath}")  # Выводим путь в консоль

# Функция определения типа шифрования
def detect_encryption(pkt):
    if pkt.haslayer(TCP) and pkt[TCP].dport in [443, 993, 995, 465]:  # Порты HTTPS, IMAPS, SMTPS
        if pkt.haslayer(Raw):  # Если есть полезная нагрузка (SSL Handshake)
            payload = bytes(pkt[Raw])
            if payload.startswith(b"\x16\x03\x01"):
                return "TLS 1.0"
            elif payload.startswith(b"\x16\x03\x02"):
                return "TLS 1.1"
            elif payload.startswith(b"\x16\x03\x03"):
                return "TLS 1.2"
            elif payload.startswith(b"\x16\x03\x04"):
                return "TLS 1.3"
        return "Зашифрованный трафик (SSL/TLS)"
    return "Нет шифрования"

# Функция обработки пакетов
def packet_handler(pkt):
    if pkt.haslayer(IP):  # Если пакет IP
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        protocol = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "Other"
        encryption = detect_encryption(pkt)  # Определяем шифрование
        log_entry = f"IP {src_ip} → {dst_ip} | Протокол: {protocol} | Шифрование: {encryption}"

        if pkt.haslayer(TCP):
            write_to_file("tcp.log", log_entry)
            if "TLS" in encryption or "SSL" in encryption:
                write_to_file("tls.log", log_entry)  # Логируем TLS

        elif pkt.haslayer(UDP):
            write_to_file("udp.log", log_entry)

        print(log_entry)  # Выводим в консоль

    elif pkt.haslayer(ARP):  # Если это ARP-запрос
        log_entry = f"ARP Запрос: {pkt.summary()}"
        write_to_file("arp.log", log_entry)
        print(log_entry)

# Запуск анализа трафика в реальном времени
print("Анализ трафика... (нажмите Ctrl+C для остановки)")
sniff(prn=packet_handler, store=False)
