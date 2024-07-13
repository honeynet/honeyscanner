import tkinter as tk
import sys
import threading
from main import run_honeyscanner, print_ascii_art_honeyscanner
from tkinter import Text

class TextRedirector:
    def __init__(self, text_widget):
        self.text_widget = text_widget

    def write(self, string):
        self.text_widget.insert('end', string)
        self.text_widget.see('end')  # Scroll to the end

    def flush(self):
        pass

def main():
    root = tk.Tk()
    root.title("Honeyscanner GUI")
    root.geometry("800x600")  # Set the window size to 800x600 pixels

    # Default values
    default_values = {
        "honeypot": "cowrie",
        "honeypot_version": "2.5.0",
        "target_ip": "127.0.0.1",
        "port": "2222",
        "username": "root",
        "password": "1234"
    }

    # Create GUI elements
    honeypot_label = tk.Label(root, text="Honeypot:")
    honeypot_label.grid(row=0, column=0, sticky="w", padx=10, pady=5)
    honeypot_entry = tk.Entry(root)
    honeypot_entry.insert(0, default_values["honeypot"])
    honeypot_entry.grid(row=0, column=1, padx=10, pady=5, sticky="ew")

    honeypot_version_label = tk.Label(root, text="Honeypot Version:")
    honeypot_version_label.grid(row=1, column=0, sticky="w", padx=10, pady=5)
    honeypot_version_entry = tk.Entry(root)
    honeypot_version_entry.insert(0, default_values["honeypot_version"])
    honeypot_version_entry.grid(row=1, column=1, padx=10, pady=5, sticky="ew")

    target_ip_label = tk.Label(root, text="Target IP:")
    target_ip_label.grid(row=2, column=0, sticky="w", padx=10, pady=5)
    target_ip_entry = tk.Entry(root)
    target_ip_entry.insert(0, default_values["target_ip"])
    target_ip_entry.grid(row=2, column=1, padx=10, pady=5, sticky="ew")

    port_label = tk.Label(root, text="Port:")
    port_label.grid(row=3, column=0, sticky="w", padx=10, pady=5)
    port_entry = tk.Entry(root)
    port_entry.insert(0, default_values["port"])
    port_entry.grid(row=3, column=1, padx=10, pady=5, sticky="ew")

    username_label = tk.Label(root, text="Username:")
    username_label.grid(row=4, column=0, sticky="w", padx=10, pady=5)
    username_entry = tk.Entry(root)
    username_entry.insert(0, default_values["username"])
    username_entry.grid(row=4, column=1, padx=10, pady=5, sticky="ew")

    password_label = tk.Label(root, text="Password:")
    password_label.grid(row=5, column=0, sticky="w", padx=10, pady=5)
    password_entry = tk.Entry(root, show="*")
    password_entry.insert(0, default_values["password"])
    password_entry.grid(row=5, column=1, padx=10, pady=5, sticky="ew")

    passive_attack_var = tk.BooleanVar()
    passive_attack_checkbox = tk.Checkbutton(root, text="Run Passive Attacks", variable=passive_attack_var)
    passive_attack_checkbox.grid(row=6, column=0, columnspan=2, padx=10, pady=5)

    active_attack_var = tk.BooleanVar()
    active_attack_checkbox = tk.Checkbutton(root, text="Run Active Attacks", variable=active_attack_var)
    active_attack_checkbox.grid(row=7, column=0, columnspan=2, padx=10, pady=5)

    output_label = tk.Label(root, text="Output:")
    output_label.grid(row=8, column=0, sticky="w", padx=10, pady=5)
    output_text = tk.Text(root, height=20, width=100, wrap="word")
    output_text.grid(row=9, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")

    status_label = tk.Label(root, text="")
    status_label.grid(row=10, column=0, columnspan=2, padx=10, pady=5)

    text_redirector = TextRedirector(output_text)

    def run_scan():
        honeypot = honeypot_entry.get()
        version = honeypot_version_entry.get()
        target_ip = target_ip_entry.get()
        port = int(port_entry.get())
        username = username_entry.get()
        password = password_entry.get()
        passive_attack = passive_attack_var.get()
        active_attack = active_attack_var.get()

        def target():
            sys.stdout = text_redirector
            sys.stderr = text_redirector
            try:
                run_honeyscanner(honeypot, version, target_ip, port, username, password, passive_attack, active_attack, terminal=text_redirector)
            finally:
                sys.stdout = sys.__stdout__
                sys.stderr = sys.__stderr__

        thread = threading.Thread(target=target)
        thread.start()

    def reset_fields():
        for entry in (honeypot_entry, honeypot_version_entry, target_ip_entry, port_entry, username_entry, password_entry):
            entry.delete(0, tk.END)
            entry.insert(0, "")

    def stop_scan():
        status_label.config(text="Scan stopped")

    def play_scan():
        status_label.config(text="Scan resumed")
        run_scan()
    
    def clear_output():
        output_text.delete('1.0', tk.END)

    scan_button = tk.Button(root, text="Run Scanner", command=run_scan)
    scan_button.grid(row=8, column=1, padx=10, pady=5, sticky="ew")

    clear_button = tk.Button(root, text="Clear", command=clear_output)
    clear_button.grid(row=11, column=0, columnspan=2, padx=10, pady=5, sticky="ew")

    # Make the text widget and the root window resizable
    root.columnconfigure(1, weight=1)
    root.rowconfigure(9, weight=1)

    root.mainloop()

if __name__ == "__main__":
    main()
