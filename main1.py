# import tkinter as tk
# import subprocess,time
# import os

# def connect_to_openVPN(config_file,username,password):
#     args = ["C:\\Program Files\\OpenVPN\\bin\\openvpn-gui.exe", "--config", config_file,"--auth-user-pass", "auth.txt"]

#     return subprocess.Popen(args)

# def disconnect_from_openVPN(process):
#     process.terminate()

# if __name__ == "__main__":
#     config_file = "F:\\SE PROJECT\\vpnbook-us1-tcp80.ovpn"
#     username = "vpnbook"
#     password = "b7dh4n3"

#     process = connect_to_openVPN(config_file, username, password)
#     print("Connected to VPN")
#     time.sleep(15)


import subprocess
import os

config_file = "F:\\SE PROJECT\\vpnbook-us1-tcp80.ovpn"
openvpn_path = "C:\\Program Files\\OpenVPN\\bin\\openvpn-gui.exe"

# def open_vpn(config_file, username, password):
#   """Opens a VPN connection using the specified config file and credentials."""

#   # Create a subprocess object to run the OpenVPN command.
#   subprocess.call(["C:\\Program Files\\OpenVPN\\bin\\openvpn-gui.exe", "--config", config_file, "--username", username, "--password", password])

# # Open the VPN connection using the specified config file and credentials.
# open_vpn("F:\\SE PROJECT\\vpnbook-us1-tcp80.ovpn", "vpnbook", "b7dh4n3")

def connect_vpn():
    cmd = [openvpn_path, "--config", config_file]
    subprocess.Popen(cmd)


def disconnect_vpn():
    os.system("taskkill /im openvpn.exe /f")

connect_vpn()