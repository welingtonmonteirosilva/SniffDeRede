import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from scapy.layers.inet import IP, TCP, UDP
from scapy.sendrecv import sniff
import threading

class WelMapApp:
    def __init__(self, master):
        self.master = master
        master.title("WelMap - Intrusion Detection System")

        self.packet_text = ScrolledText(master, height=20, width=50)
        self.packet_text.pack(pady=10)

        self.start_button = tk.Button(master, text="Start Detection", command=self.start_detection)
        self.start_button.pack(pady=5)

        self.stop_button = tk.Button(master, text="Stop Detection", command=self.stop_detection, state=tk.DISABLED)
        self.stop_button.pack(pady=5)

        self.is_detection_running = False
        self.packet_capture_thread = None

    def start_detection(self):
        if not self.is_detection_running:
            self.is_detection_running = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.packet_text.delete(1.0, tk.END)
            self.packet_capture_thread = threading.Thread(target=self.detect_intrusions)
            self.packet_capture_thread.start()

    def stop_detection(self):
        self.is_detection_running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def analyze_packet(self, packet):
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
            src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else "N/A"
            dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else "N/A"
            self.packet_text.insert(tk.END, f"Detected {protocol} packet from {ip_src}:{src_port} to {ip_dst}:{dst_port}\n")
            self.packet_text.see(tk.END)

    def detect_intrusions(self):
        self.packet_text.insert(tk.END, "Iniciando WelMap...\n")
        self.packet_text.see(tk.END)
        sniff(filter="ip", prn=self.analyze_packet, stop_filter=lambda x: not self.is_detection_running)

root = tk.Tk()
app = WelMapApp(root)
root.mainloop()
