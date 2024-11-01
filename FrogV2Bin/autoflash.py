#!/usr/bin/env python3

import glob
import time
import subprocess
import os

def get_usb_port():
    ports = glob.glob('/dev/cu.usbmodem*')
    return ports[0] if ports else None

def flash_device(port):
    cmd = [
        'esptool.py',
        '--chip', 'esp32c3',
        '--port', port,
        'write_flash',
        '0x0', 'FrogV2.ino.bootloader.bin',
        '0x8000', 'FrogV2.ino.partitions.bin',
        '0xe000', 'boot_app0.bin',
        '0x10000', 'FrogV2.ino.bin'
    ]
    
    try:
        subprocess.run(cmd, check=True)
        print("Flash successful!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Flash failed with error: {e}")
        return False

def main():
    print("Starting auto-flash script...")
    print("Waiting for ESP32 device...")
    
    last_port = None
    
    while True:
        port = get_usb_port()
        
        if port:
            if port != last_port:  # Only flash if it's a new connection
                print(f"ESP32 detected at {port}")
                
                if flash_device(port):
                    last_port = port
                else:
                    last_port = None
        else:
            if last_port:
                print("Device disconnected. Waiting for reconnection...")
                last_port = None
                
        time.sleep(0.5)  # Check every 500ms

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScript terminated by user")
