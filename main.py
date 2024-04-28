import os
import tkinter as tk
from tkinter import filedialog, ttk
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import xml.etree.ElementTree as ET
import sys
import re

def decrypt_esfm_file(file_path, np_com_id, trophy_key, output_folder, update_progress):
    iv = bytes([0] * 16)
    cipher = AES.new(trophy_key, AES.MODE_CBC, iv)
    key = cipher.encrypt(np_com_id.ljust(16, '\0').encode())

    with open(file_path, 'rb') as file:
        encrypted_data = file.read()

    total_size = len(encrypted_data)
    chunk_size = AES.block_size

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = bytearray()
    for i in range(0, total_size, chunk_size):
        chunk = encrypted_data[i:i + chunk_size]
        decrypted_chunk = cipher.decrypt(chunk)
        decrypted_data.extend(decrypted_chunk)
        update_progress((i + chunk_size) * 100 / total_size) 
    
    decrypted_data = unpad(decrypted_data, AES.block_size)
    decrypted_data = ''.join(chr(byte) for byte in decrypted_data if 32 <= byte <= 126 or byte in (9, 10, 13))

    try:
        decrypted_xml = ET.fromstring(decrypted_data)
    except ET.ParseError as e:
        print("Error parsing decrypted XML:", e)
        return None

    output_file_path = os.path.join(output_folder, os.path.basename(file_path)[:-5] + ".xml")
    with open(output_file_path, 'w', encoding='utf-8') as output_file:
        output_file.write(decrypted_data)

    return output_file_path


def update_progress(value):
    progress_bar['value'] = value
    root.update_idletasks()

def update_xml_display(content):
    xml_display.delete("1.0", tk.END)
    xml_display.insert(tk.END, content)

def select_file():
    file_path = filedialog.askopenfilename(filetypes=[("ESFM files", "*.ESFM")])
    file_entry.delete(0, tk.END)
    file_entry.insert(0, file_path)

def select_folder():
    folder_path = filedialog.askdirectory()
    folder_entry.delete(0, tk.END)
    folder_entry.insert(0, folder_path)

def decrypt_file():
    file_path = file_entry.get()
    folder_path = folder_entry.get()
    np_com_id = np_com_id_entry.get()

    if not re.match(r'^NPWR\d{5}_\d{2}$', np_com_id):
        result_label.config(text="Decryption fail, check NP Communication ID (format: NPWRYYYYY_ZZ)")
        return

    trophy_key = bytes([
        0x21, 0xF4, 0x1A, 0x6B, 0xAD, 0x8A, 0x1D, 0x3E,
        0xCA, 0x7A, 0xD5, 0x86, 0xC1, 0x01, 0xB7, 0xA9
    ])

    decrypted_file_path = decrypt_esfm_file(file_path, np_com_id, trophy_key, folder_path, update_progress)
    if decrypted_file_path:
        with open(decrypted_file_path, 'r', encoding='utf-8') as decrypted_file:
            decrypted_content = decrypted_file.read()
            update_xml_display(decrypted_content)
        result_label.config(text=f"Decrypted file saved at: {decrypted_file_path}")
    else:
        result_label.config(text="Error decrypting file.")

root = tk.Tk()
root.title("ESFM Decrypter")
root.configure(bg='#ADD8E6')

screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
tool_width = screen_width * 3 // 4  
tool_height = screen_height * 3 // 5
root.geometry(f"{tool_width}x{tool_height}")

ascii_label = tk.Label(root, text="""
                    ___       ___             ____  __       __        __________                
  _____ _____     __| _/____   \_ |__ ___ __  |    |/ _|_____/  |______ \______   \_____    ____  
 /     \__  \   / __ |/ __ \   | __ <   |  | |      <_/ __ \   __\__  \ |     ___/\__  \  /    \ 
|  Y Y  \/ __ \_/ /_/ \  ___/   | \_\ \___  | |    |  \  ___/|  |  / __ \|    |     / __ \|   |  \ 
|__|_|  (____  /\____ |\___  >  |___  / ____| |____|__ \___  >__| (____  /____|    (____  /___|  /
      \/     \/      \/    \/       \/\/              \/   \/          \/               \/     \/ 
""", font=("Courier", 10), justify="center", bg='#ADD8E6')
ascii_label.pack(pady=20)

main_frame = ttk.Frame(root)
main_frame.pack(pady=10)
style = ttk.Style()
style.configure('My.TFrame', background='#ADD8E6')
main_frame.configure(style='My.TFrame')

input_frame = ttk.Frame(main_frame)
input_frame.grid(row=0, column=0, padx=10, pady=5, sticky="nsew")
input_frame.configure(style='My.TFrame')

file_label = tk.Label(input_frame, text="Select ESFM File:", font=("Helvetica", 10), bg='#ADD8E6')
file_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
file_entry = tk.Entry(input_frame, width=60, font=("Helvetica", 10))
file_entry.grid(row=0, column=1, padx=10, pady=5)
file_button = tk.Button(input_frame, text="Browse", command=select_file, font=("Helvetica", 10), bg="black", fg="white", relief="raised")
file_button.grid(row=0, column=2, padx=10, pady=5)

folder_label = tk.Label(input_frame, text="Select Output Folder:", font=("Helvetica", 10), bg='#ADD8E6')
folder_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")
folder_entry = tk.Entry(input_frame, width=60, font=("Helvetica", 10))
folder_entry.grid(row=1, column=1, padx=10, pady=5)
folder_button = tk.Button(input_frame, text="Browse", command=select_folder, font=("Helvetica", 10), bg="black", fg="white", relief="raised")
folder_button.grid(row=1, column=2, padx=10, pady=5)

np_com_id_label = tk.Label(input_frame, text="Enter NP Communication ID:", font=("Helvetica", 10), bg='#ADD8E6')
np_com_id_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")
np_com_id_entry = tk.Entry(input_frame, width=60, font=("Helvetica", 10))
np_com_id_entry.grid(row=2, column=1, padx=10, pady=5)

decrypt_button = tk.Button(main_frame, text="Decrypt", command=decrypt_file, font=("Helvetica", 12, "bold"), bg="black", fg="white", relief="raised")
decrypt_button.grid(row=1, column=0, padx=10, pady=10)

progress_bar = ttk.Progressbar(main_frame, orient="horizontal", length=300, mode="determinate")
progress_bar.grid(row=2, column=0, padx=10, pady=5)

result_label = tk.Label(main_frame, text="", font=("Helvetica", 10), bg='#ADD8E6')
result_label.grid(row=3, column=0, padx=10, pady=5)

xml_display = tk.Text(main_frame, wrap=tk.NONE, font=('Courier', 8))
xml_display.grid(row=0, column=1, rowspan=4, padx=10, pady=5, sticky="nsew")
scroll_y = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=xml_display.yview)
scroll_y.grid(row=0, column=2, rowspan=4, sticky="ns")
scroll_x = ttk.Scrollbar(main_frame, orient=tk.HORIZONTAL, command=xml_display.xview)
scroll_x.grid(row=4, column=1, sticky="ew", pady=(0, 5))  
xml_display.config(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)

def open_readme():
    script_dir = os.path.dirname(sys.argv[0])
    readme_path = os.path.join(script_dir, "README.md")
    os.system(f"start {readme_path}")


def open_discord():
    os.system("start https://discord.gg/bgYY7wWvSD")

def open_github():
    os.system("start https://github.com/lKetaPanl")

menubar = tk.Menu(root)
help_menu = tk.Menu(menubar, tearoff=0)
menubar.add_cascade(label="Help", menu=help_menu)

help_menu.add_command(label="Readme", command=open_readme)
help_menu.add_command(label="Discord Server", command=open_discord)
help_menu.add_command(label="GitHub IKetaPanI", command=open_github)

root.config(menu=menubar)

root.mainloop()
