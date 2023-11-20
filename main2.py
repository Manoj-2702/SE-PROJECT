# import requests
# import speedtest
# import tkinter as tk

# # def get_public_ip():
# #     return requests.get('https://api64.ipify.org?format=json').json()['ip']

# # def run_speed_test():
# #     try:
# #         st = speedtest.Speedtest()
# #         download_speed = st.download() / 1_000_000  # Convert to Mbps
# #         upload_speed = st.upload() / 1_000_000  # Convert to Mbps
# #         return download_speed, upload_speed
# #     except speedtest.SpeedtestException as e:
# #         return None, None

# # ip = get_public_ip()
# # print(f"IP: {ip}")

# # download, upload = run_speed_test()

# # if download is not None and upload is not None:
# #     print(f"Download Speed: {download:.2f} Mbps")
# #     print(f"Upload Speed: {upload:.2f} Mbps")
# # else:
# #     print("Speed test failed. Check your network connection.")


# class SpeedTestApp:
#     def __init__(self,root):
#         self.root = root
#         self.root.title("Speed Test")

#         self.root.geometry("500x500")

#         self.ip_label = tk.Label(root, text="Public IP:")
#         self.ip_label.pack()

#         self.download_label = tk.Label(root, text="Download Speed: N/A Mbps")
#         self.download_label.pack()

#         self.upload_label = tk.Button(root, text="Upload Speed: N/A Mbps")
#         self.upload_label.pack()

#         self.get_ip_button = tk.Button(root, text="Get Public IP", command=self.get_public_ip)
#         self.get_ip_button.pack()

#         self.speed_test_button = tk.Button(root, text="Run Speed Test", command=self.run_speed_test)
#         self.speed_test_button.pack()

    
#     def get_public_ip(self):
#         return requests.get('https://api64.ipify.org?format=json').json()['ip']
    

#     def run_speed_test(self):
#         try:
#             st = speedtest.Speedtest()
#             download_speed = st.download() / 1_000_000  # Convert to Mbps
#             upload_speed = st.upload() / 1_000_000  # Convert to Mbps
#             self.download_label.config(text=f"Download Speed: {download_speed:.2f} Mbps")
#             self.upload_label.config(text=f"Upload Speed: {upload_speed:.2f} Mbps")
#         except speedtest.SpeedtestException as e:
#             self.download_label.config(text="Download Speed: N/A Mbps")
#             self.upload_label.config(text="Upload Speed: N/A Mbps")
        
#     # def update_speed(self):
#     #     ip = self.get_public_ip()
#     #     self.ip_label.config(text=f"Public IP: {ip}")

#     #     download, upload = self.run_speed_test()

#     #     if download is not None and upload is not None:
#     #         self.download_label.config(text=f"Download Speed: {download:.2f} Mbps")
#     #         self.upload_label.config(text=f"Upload Speed: {upload:.2f} Mbps")
#     #     else:
#     #         self.download_label.config(text="Download Speed: N/A Mbps")
#     #         self.upload_label.config(text="Upload Speed: N/A Mbps")

#         # Schedule the next update after 10 seconds (10000 milliseconds)
#         # self.root.after(10000, self.update_speed)



# if __name__ == "__main__":
#     root = tk.Tk()
#     app = SpeedTestApp(root)
#     root.mainloop()
# import os

# def check_ping():
#     hostname = "google.com"
#     response = os.system("ping -n 5 " + hostname)
#     print(response)
#     # and then check the response...
#     if response == 0:
#         pingstatus = "Network Active"
#         print(pingstatus)
#     else:
#         pingstatus = "Network Error"
#         print(pingstatus)

# check_ping()


# import subprocess

# def check_openvpn_status():
#   """Checks the status of an OpenVPN client.

#   Returns:
#     A boolean value indicating whether the OpenVPN client is running.
#   """

#   output = subprocess.check_output(['sudo', 'service', 'openvpn', 'status'])
#   return 'openvpn is running' in output

# if __name__ == '__main__':
#   if check_openvpn_status():
#     print('The OpenVPN client is running.')
#   else:
#     print('The OpenVPN client is not running.')

# import requests
# import re
# import random
# from termcolor import colored
# from bs4 import BeautifulSoup as bs4

# def DNS_Report(self,dns):
# 	url = 'http://viewdns.info/dnsreport/?domain='+dns
# 	Session = requests.Session()
# 	Session.headers.update({
#                     'UserAgent':random.choice(self.user_agents),
#                   'Host' : 'viewdns.info',
#                 })

# 	request = Session.get(url) 
# 	res = request.text
# 	#sou = bs4(res, 'html.parser')
# 	rgx = re.findall( r'[0-9]+(?:\.[0-9]+){3}', res )
# 	print (colored("[*]",'white')),("Getting list: ")
# 	print("\n")
# 	print(colored("[*]",'white')),("IP: ")
# 	for ent in  rgx:
# 	    print (colored("[+]",'blue')),("IP: %s" % ent)
	    
#     # print("\n")
#     print (colored("[*]",'white')),("Domain: ")
# 	print("\n")
# 	for ents in re.findall(self.WEB_URL_REGEX,res):
# 	    if ents.startswith("https://") or ents.startswith("http://") or ents.endswith(".js") or ents.startswith("viewdns") or ents.startswith("ViewDNS"):
# 		    pass
# 	    else:
# 		    print (colored("[+]",'blue')),("Domain: %s" % ents)


import requests
import json
import os
# URL=""
# ipify_json_endpoint = "https://api.ipify.org?format=json"

# def get_public_ip():
#     global URL
#     try:
#         response = requests.get(ipify_json_endpoint)
#         ip_address= json.loads(response.text)["ip"]
#         URL=ip_address
#     except:
#         return None
    
# def TraceRoute():
#     global URL
#     ip=URL
#     windows = 'tracert '+ip
#     os.system(windows)   

# get_public_ip()
# TraceRoute()


import subprocess

# def verify_openvpn_tls(openvpn_config_file):
#     try:
#         # Extract the PEM-encoded certificate from the OpenVPN configuration file
#         pem_cert_output = subprocess.check_output(["powershell", "-Command", 
#                                                   "(Get-Content -Raw '{}') -match '-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----' -replace '[`r`n]', ''".format(openvpn_config_file)],
#                                                  text=True)
#         # Save the PEM certificate to a temporary file
#         with open("temp_cert.pem", "w") as temp_file:
#             temp_file.write(pem_cert_output)

#         # Use openssl to display certificate details
#         openssl_command = ["openssl", "x509", "-text", "-noout", "-in", "temp_cert.pem"]
#         openssl_output = subprocess.check_output(openssl_command, text=True)

#         # Print the certificate details
#         print(openssl_output)

#     except subprocess.CalledProcessError as e:
#         print(f"Error executing command: {e}")
#     finally:
#         # Clean up: Remove the temporary certificate file
#         try:
#             subprocess.run(["del", "temp_cert.pem"],shell=True, check=True)
#         except subprocess.CalledProcessError as e:
#             print(f"Error cleaning up temporary files: {e}")

# # Example usage
# openvpn_config_file_path = "F:\\SE Project\\vpnbook-us1-tcp80.ovpn"
# verify_openvpn_tls(openvpn_config_file_path)



# from cryptography import x509
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import serialization,hashes
# from cryptography.hazmat.primitives.asymmetric import rsa
# import subprocess
# import os

# def verify_openvpn_tls(openvpn_config_file):
#     try:
#         # Read the OpenVPN configuration file
#         with open(openvpn_config_file, 'r') as file:
#             config_content = file.read()

#         # Extract the certificate part from the OpenVPN configuration
#         cert_start = config_content.find('-----BEGIN CERTIFICATE-----')
#         cert_end = config_content.find('-----END CERTIFICATE-----', cert_start)
#         pem_cert = config_content[cert_start:cert_end + len('-----END CERTIFICATE-----')]

#         # Parse the certificate using cryptography library
#         cert = x509.load_pem_x509_certificate(pem_cert.encode(), default_backend())

#         # Display certificate details
#         print(f"Subject: {cert.subject}")
#         print(f"Issuer: {cert.issuer}")
#         print(f"Serial Number: {cert.serial_number}")
#         print(f"Valid From: {cert.not_valid_before}")
#         print(f"Valid Until: {cert.not_valid_after}")
#         public_key = cert.public_key()
#         if isinstance(public_key, rsa.RSAPublicKey):
#             print(f"Public Key Algorithm: RSA (OpenSSH format)")
#         elif isinstance(public_key, serialization.ECPrivateKey):
#             print(f"Public Key Algorithm: Elliptic Curve (EC)")
#         else:
#             print(f"Public Key Algorithm: {public_key.__class__.__name__}")
#         print(f"Signature Algorithm: {cert.signature_algorithm_oid}")

#     except Exception as e:
#         print(f"Error: {e}")

# # Example usage
# openvpn_config_file_path = "F:\\SE Project\\vpnbook-us1-tcp80.ovpn"
# verify_openvpn_tls(openvpn_config_file_path)

# import scapy.all as scapy

# def packet_callback(packet):
#     if packet.haslayer(scapy.IP):
#         ip_src = packet[scapy.IP].src
#         print(ip_src)
#         ip_dst = packet[scapy.IP].dst
#         print(ip_dst)
#         fragment_offset = packet[scapy.IP].frag
#         print(fragment_offset)

#         if fragment_offset != 0:
#             # This is a fragment, reassemble
#             payload = packet[scapy.Raw].load
#             print(f"Reassembling fragment from {ip_src} to {ip_dst}")
#             reassembled_payload[ip_src + ip_dst] += payload

#             # Check if this is the last fragment
#             if not packet[scapy.IP].MF:
#                 print("Last fragment received. Reassembled Payload:")
#                 print(reassembled_payload[ip_src + ip_dst].decode('utf-8'))
#         else:
#             # This is not a fragment, clear the reassembly buffer
#             reassembled_payload[ip_src + ip_dst] = b""

# # Dictionary to store reassembled payloads based on source and destination IP
# reassembled_payload = {}
# # Sniff for IPv4 traffic, calling packet_callback for each packet
# scapy.sniff(filter="ip", prn=packet_callback, store=0)



import subprocess

def verify_no_packet_loss(destination, count=4):
    try:
        # Run the ping command
        result = subprocess.run(['ping', '-n', str(count), destination], capture_output=True, text=True)

        # Check if the command was successful
        if result.returncode == 0:
            # Analyze the output to check for packet loss
            packet_loss_percentage = parse_packet_loss(result.stdout)
            if packet_loss_percentage == 0.0:
                print("Connection established with no packet loss.")
            else:
                print(f"Packet loss detected: {packet_loss_percentage}%")
        else:
            print("Error executing ping command.")

    except Exception as e:
        print(f"Error: {e}")

def parse_packet_loss(ping_output):
    # Parse the output of the ping command to extract packet loss percentage
    # Example output: "Ping statistics for 8.8.8.8:\n    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),"
    lines = ping_output.splitlines()
    for line in lines:
        if "loss" in line:
            packet_loss_percentage = float(line.split('(')[1].split('%')[0])
            return packet_loss_percentage
    return None

# Example usage
destination_host = "google.com"
verify_no_packet_loss(destination_host)