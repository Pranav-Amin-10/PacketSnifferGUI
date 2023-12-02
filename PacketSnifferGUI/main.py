import tkinter as tk
from tkinter import ttk, scrolledtext
import scapy.all as scapy
from threading import Thread

# Global variables for packet capture
packet_count = 0
packet_capture_active = False


def start_packet_capture():
    global packet_count, packet_capture_active
    if not packet_capture_active:
        packet_capture_active = True
        packet_count = 0
        result_text.delete(1.0, tk.END)  # Clear the result text
        capture_thread = Thread(target=sniff_and_save_packets)
        capture_thread.start()


def stop_packet_capture():
    global packet_capture_active
    packet_capture_active = False


def sniff_and_save_packets():
    interface = interface_entry.get()
    output_file = output_file_entry.get()
    try:
        packet_count_limit = int(packet_count_entry.get())
    except ValueError:
        update_result_text("Invalid packet count.")
        return

    with open(output_file, "w") as file:
        file.write("Packet Capture Details:\n")

    update_result_text("Sniffing packets... (Press 'Stop' to finish)")

    while packet_capture_active:
        if packet_count < packet_count_limit:
            packet = scapy.sniff(iface=interface, count=1)[0]
            save_packet_to_file(packet, output_file)
            packet_count += 1
        else:
            update_result_text("Packet capture complete.")
            packet_capture_active = False


def save_packet_to_file(packet, filename):
    with open(filename, "a") as file:
        file.write("Packet Details:\n")
        file.write(f"Source IP: {packet[scapy.IP].src}\n")
        file.write(f"Destination IP: {packet[scapy.IP].dst}\n")
        if scapy.TCP in packet:
            file.write(f"Source Port: {packet[scapy.TCP].sport}\n")
            file.write(f"Destination Port: {packet[scapy.TCP].dport}\n")
        elif scapy.UDP in packet:
            file.write(f"Source Port: {packet[scapy.UDP].sport}\n")
            file.write(f"Destination Port: {packet[scapy.UDP].dport}\n")
        file.write("Packet Contents:\n")
        file.write(str(packet) + "\n\n")


def update_result_text(text):
    result_text.insert(tk.END, text + "\n")
    result_text.see(tk.END)


# Create the main window
window = tk.Tk()
window.title("Packet Sniffer")

# Create and configure widgets
frame = ttk.Frame(window)
frame.grid(column=0, row=0, padx=10, pady=10)

interface_label = ttk.Label(frame, text="Interface:")
interface_label.grid(column=0, row=0)
interface_entry = ttk.Entry(frame)
interface_entry.grid(column=1, row=0)

output_file_label = ttk.Label(frame, text="Output File:")
output_file_label.grid(column=0, row=1)
output_file_entry = ttk.Entry(frame)
output_file_entry.grid(column=1, row=1)

packet_count_label = ttk.Label(frame, text="Packet Count Limit:")
packet_count_label.grid(column=0, row=2)
packet_count_entry = ttk.Entry(frame)
packet_count_entry.grid(column=1, row=2)

start_button = ttk.Button(frame, text="Start Capture", command=start_packet_capture)
start_button.grid(column=0, row=3)

stop_button = ttk.Button(frame, text="Stop Capture", command=stop_packet_capture)
stop_button.grid(column=1, row=3)

result_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=50, height=15)
result_text.grid(column=0, row=4, columnspan=2)

# Start the main loop
window.mainloop()
