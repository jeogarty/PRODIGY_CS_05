import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, IP, get_if_list
import threading
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import time

class PacketSniffer:
    def __init__(self, master):
        self.master = master
        master.title("Packet Sniffer Tool")

        self.running = False
        self.packets = []
        self.protocol_count = {}
        self.time_stamps = []
        self.protocol_values = []

        # Protocol mapping
        self.protocol_mapping = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
        }

        # Configure grid for resizing
        master.rowconfigure(2, weight=1)
        master.columnconfigure(0, weight=1)
        master.columnconfigure(1, weight=1)

        # Dropdown for network devices
        self.device_label = tk.Label(master, text="Select Network Interface:")
        self.device_label.grid(row=0, column=0, padx=5, pady=5)

        self.device_var = tk.StringVar()
        self.device_dropdown = ttk.Combobox(master, textvariable=self.device_var, width=30)
        self.device_dropdown.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.device_dropdown['values'] = self.get_interfaces()

        # Start and Stop Buttons
        self.start_button = tk.Button(master, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.grid(row=1, column=0, padx=5, pady=5)

        self.stop_button = tk.Button(master, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.grid(row=1, column=1, padx=5, pady=5)

        # Table for displaying captured packets
        self.tree = ttk.Treeview(master, columns=("Source IP", "Destination IP", "Protocol", "Length"), show="headings")
        self.tree.heading("Source IP", text="Source IP")
        self.tree.heading("Destination IP", text="Destination IP")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Length", text="Length")
        self.tree.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")

        # Center align table values
        for column in ("Source IP", "Destination IP", "Protocol", "Length"):
            self.tree.column(column, anchor="center")

        # Graph area for monitoring protocol usage
        self.figure, self.ax = plt.subplots(figsize=(5, 3))
        self.canvas = FigureCanvasTkAgg(self.figure, master)
        self.canvas_widget = self.canvas.get_tk_widget()
        self.canvas_widget.grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")

        self.update_graph()

    def get_interfaces(self):
        # Get list of available network interfaces
        try:
            return get_if_list()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch interfaces: {str(e)}")
            return []

    def packet_callback(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            length = len(packet)

            protocol_name = self.protocol_mapping.get(protocol, str(protocol))

            self.packets.append((src_ip, dst_ip, protocol_name, length))
            self.tree.insert("", "end", values=(src_ip, dst_ip, protocol_name, length))

            self.protocol_count[protocol_name] = self.protocol_count.get(protocol_name, 0) + 1
            self.time_stamps.append(time.time())
            self.protocol_values.append(len(self.packets))

    def start_sniffing(self):
        device = self.device_var.get()
        if not device:
            messagebox.showwarning("Warning", "Please select a network interface.")
            return

        self.running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        self.sniffer_thread = threading.Thread(target=self.sniff_packets, args=(device,), daemon=True)
        self.sniffer_thread.start()

    def sniff_packets(self, device):
        sniff(iface=device, prn=self.packet_callback, stop_filter=lambda x: not self.running)

    def stop_sniffing(self):
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def update_graph(self):
        if self.running or self.time_stamps:
            self.ax.clear()
            self.ax.plot(self.time_stamps, self.protocol_values, label="Packet Count")
            self.ax.set_title("Protocol Activity Over Time")
            self.ax.set_xlabel("Time (s)")
            self.ax.set_ylabel("Packet Count")
            self.ax.legend()
            self.canvas.draw()

        self.master.after(1000, self.update_graph)


if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSniffer(root)
    root.mainloop()
