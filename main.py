import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
from scapy.all import sniff

class NetworkProtocolAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Protocol Analyzer")

        # Frame for buttons
        self.button_frame = tk.Frame(self.root)
        self.button_frame.pack(pady=5)

        # Start and stop buttons
        self.start_button = tk.Button(self.button_frame, text="Start", command=self.start_analysis)
        self.start_button.pack(side=tk.LEFT, padx=5)
        self.stop_button = tk.Button(self.button_frame, text="Stop", command=self.stop_analysis, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # Text area for displaying packets
        self.text_area = scrolledtext.ScrolledText(self.root, width=100, height=20)
        self.text_area.pack(padx=10, pady=10)

        # Initialize variables
        self.running = False

    def start_analysis(self):
        self.running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        threading.Thread(target=self.analyze_packets).start()

    def stop_analysis(self):
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def analyze_packets(self):
        sniff(prn=self.packet_handler, store=0)

    def packet_handler(self, packet):
        try:
            if packet.haslayer("TCP"):
                src_ip = packet["IP"].src
                dst_ip = packet["IP"].dst
                src_port = packet["TCP"].sport
                dst_port = packet["TCP"].dport
                tcp_payload = bytes(packet["TCP"].payload).hex()

                # Display information
                self.text_area.insert(tk.END, f"Source IP: {src_ip}\n")
                self.text_area.insert(tk.END, f"Destination IP: {dst_ip}\n")
                self.text_area.insert(tk.END, f"Source Port: {src_port}\n")
                self.text_area.insert(tk.END, f"Destination Port: {dst_port}\n")
                self.text_area.insert(tk.END, f"TCP Payload: {tcp_payload}\n")
                self.text_area.insert(tk.END, "-" * 50 + "\n")

                # Save information to a file
                with open("packet_log.txt", "a") as file:
                    file.write(f"Source IP: {src_ip}\n")
                    file.write(f"Destination IP: {dst_ip}\n")
                    file.write(f"Source Port: {src_port}\n")
                    file.write(f"Destination Port: {dst_port}\n")
                    file.write(f"TCP Payload: {tcp_payload}\n")
                    file.write("-" * 50 + "\n")

        except Exception as e:
            print(e)

    def clear_text_area(self):
        self.text_area.delete(1.0, tk.END)


def main():
    root = tk.Tk()
    app = NetworkProtocolAnalyzer(root)
    root.mainloop()

if __name__ == "__main__":
    main()
