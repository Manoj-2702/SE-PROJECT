import requests
import speedtest
import tkinter as tk
import json
import os
import subprocess
from termcolor import colored
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import scapy.all as scapy
from dotenv import load_dotenv
from random import randint
from platform import system as system_name
from subprocess import call as system_call
from urllib.request import urlopen

load_dotenv()

destination_host=os.environ.get("DESTINATION_HOST")
config_file_path=os.environ.get("CONFIG_PATH")
ipify_json_endpoint =os.environ.get("API_ENDPOINT")


BG_COLOR = "#f0f0f0"  # Light gray
LABEL_COLOR = "#333333"  # Dark gray
BUTTON_COLOR = "#4CAF50" 


# import threading
URL=""

def get_public_ip():
    global URL
    try:
        response = requests.get(ipify_json_endpoint)
        ip_address= json.loads(response.text)["ip"]
        URL=ip_address
        ip_label.config(text=f"Public IP: {ip_address}", fg=LABEL_COLOR)
    except:
        return None


def run_speed_test():
    try:
        st = speedtest.Speedtest()
        download_speed = st.download() / 1_000_000  # Convert to Mbps
        upload_speed = st.upload() / 1_000_000  # Convert to Mbps
        return download_speed, upload_speed
    except speedtest.SpeedtestException as e:
        return None, None


def update_speed_labels():
    download, upload = run_speed_test()

    if download is not None and upload is not None:
        download_label.config(text=f"Download Speed: {download:.2f} Mbps", fg=LABEL_COLOR)
        upload_label.config(text=f"Upload Speed: {upload:.2f} Mbps", fg=LABEL_COLOR)
    else:
        download_label.config(text="Download Speed: N/A Mbps", fg=LABEL_COLOR)
        upload_label.config(text="Upload Speed: N/A Mbps", fg=LABEL_COLOR)

    # Schedule the next speed update after 10 seconds (10000 milliseconds)
    windows.after(10000, update_speed_labels)


def check_ping():
    hostname =destination_host
    response = os.system("ping -n 5 " + hostname)
    # Update the ping status label
    if response == 0:
        ping_status_label.config(text="Network Status: Active", fg=LABEL_COLOR)
    else:
        ping_status_label.config(text="Network Status: Error", fg="red")


def TraceRoute():
    global URL
    ip=URL
    windows1 = 'tracert -h 5 '+ip
    # res=os.system(windows1)
    result = subprocess.check_output(windows1, shell=True, text=True)
    trace_label.config(text=f"TraceRoute Result:\n{result}", fg=LABEL_COLOR)
    trace_label.config(state=tk.NORMAL)  # Enable the Text widget for editing
    # trace_label.delete("1.0", tk.END)  # Clear existing text
    # trace_label.insert(tk.END, result)  # Insert the new result
    trace_label.config(state=tk.DISABLED)



def verify_openvpn_tls(openvpn_config_file):
    try:
        with open(openvpn_config_file, 'r') as file:
            config_content = file.read()

        cert_start = config_content.find('-----BEGIN CERTIFICATE-----')
        cert_end = config_content.find('-----END CERTIFICATE-----', cert_start)
        pem_cert = config_content[cert_start:cert_end + len('-----END CERTIFICATE-----')]

        cert = x509.load_pem_x509_certificate(pem_cert.encode(), default_backend())

        result_text = (
            f"Subject: {cert.subject}\n"
            f"Issuer: {cert.issuer}\n"
            f"Serial Number: {cert.serial_number}\n"
            f"Valid From: {cert.not_valid_before}\n"
            f"Valid Until: {cert.not_valid_after}\n"
            f"Signature Algorithm: {cert.signature_algorithm_oid}\n"
        )

        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            result_text += f"Public Key Algorithm: RSA (OpenSSH format)\n"
        elif isinstance(public_key, serialization.ECPrivateKey):
            result_text += f"Public Key Algorithm: Elliptic Curve (EC)\n"
        else:
            result_text += f"Public Key Algorithm: {public_key.__class__.__name__}\n"

        return result_text

    except Exception as e:
        return f"Error: {e}"


def verify_openvpn_tls_and_display_result():
    openvpn_config_file_path = config_file_path
    result = verify_openvpn_tls(openvpn_config_file_path)
    result_label.config(text=f"OpenVPN TLS Verification Result:\n{result}", fg=LABEL_COLOR)


def verify_no_packet_loss(destination, count=10):
    try:
        result = subprocess.run(['ping', '-n', str(count), destination], capture_output=True, text=True)
        if result.returncode == 0:
            packet_loss_percentage = parse_packet_loss(result.stdout)
            if packet_loss_percentage == 0.0:
                packet_loss_result.config(text="Connection established with no packet loss.", fg="green")
            else:
                packet_loss_result.config(text=f"Packet loss detected: {packet_loss_percentage}%", fg="red")
        else:
            packet_loss_result.config(text="Error executing ping command.", fg="red")
    except Exception as e:
        packet_loss_result.config(text=f"Error: {e}", fg="red")

def parse_packet_loss(ping_output):
    lines = ping_output.splitlines()
    for line in lines:
        if "loss" in line:
            packet_loss_percentage = float(line.split('(')[1].split('%')[0])
            return packet_loss_percentage
    return None


def run_verify_no_packet_loss():
    destination_host1 = destination_host  # Change to your desired destination host
    verify_no_packet_loss(destination_host1)
    # Schedule the function to run again after 5000 milliseconds (5 seconds)
    windows.after(20000, run_verify_no_packet_loss)


def perform_dns_leak_test():
    def ping1(host):
        fn = open(os.devnull, 'w')
        param = '-n' if system_name().lower() == 'windows' else '-c'
        command = ['ping', param, '1', host]
        retcode = system_call(command, stdout=fn, stderr=subprocess.STDOUT)
        fn.close()
        return retcode == 0


    leak_id = randint(1000000, 9999999)
    for x in range(0, 10):
        ping1('.'.join([str(x), str(leak_id), "bash.ws"]))

    response = urlopen("https://bash.ws/dnsleak/test/"+str(leak_id)+"?json")
    data = response.read().decode("utf-8")
    parsed_data = json.loads(data)


    result_text = "RESULT OF DNS LEAK TESTING:\n"

    print("Your IP:")
    for dns_server in parsed_data:
        if dns_server['type'] == "ip":
            if dns_server['country_name']:
                if dns_server['asn']:
                    print(dns_server['ip']+" ["+dns_server['country_name']+", " +
                        dns_server['asn']+"]")
                    result_text += f"{dns_server['ip']} [{dns_server['country_name']}, {dns_server['asn']}]\n"
                else:
                    print(dns_server['ip']+" ["+dns_server['country_name']+"]")
                    result_text += f"{dns_server['ip']} [{dns_server['country_name']}]\n"
            else:
                print(dns_server['ip'])
                result_text += f"{dns_server['ip']}\n"

    

    servers = 0
    for dns_server in parsed_data:
        if dns_server['type'] == "dns":
            servers = servers + 1

    if servers == 0:
        print("No DNS servers found")
        result_text += f"NO DNS SERVERS FOUND\n"
        dns_leak_result.config(text=result_text, fg="red")
    else:
        print("You use "+str(servers)+" DNS servers:")
        result_text += f"YOU USE {str(servers)} DNS SERVERS:\n"
        dns_leak_result.config(text=result_text, fg="green")
        for dns_server in parsed_data:
            if dns_server['type'] == "dns":
                if dns_server['country_name']:
                    if dns_server['asn']:
                        print(dns_server['ip']+" ["+dns_server['country_name'] +
                            ", " + dns_server['asn']+"]")
                        result_text += f"{dns_server['ip']} [{dns_server['country_name']}, {dns_server['asn']}]\n"
                    else:
                        print(dns_server['ip']+" ["+dns_server['country_name']+"]")
                        result_text += f"{dns_server['ip']} [{dns_server['country_name']}\n"
                else:
                    print(dns_server['ip'])
                    result_text += f"{dns_server['ip']}\n"

    print("Conclusion:")
    result_text+=f"CONCLUSION:\n"
    for dns_server in parsed_data:
        if dns_server['type'] == "conclusion":
            if dns_server['ip']:
                print(dns_server['ip'])
                result_text += f"{dns_server['ip']}\n"


    dns_leak_result.config(text=result_text, fg="orange")





windows=tk.Tk()
windows.title("Speed Test")
windows.geometry("1500x1500")
windows.configure(bg=BG_COLOR)

ip_label = tk.Label(windows, text="Your Public IP:\n")
ip_label.pack()
get_ip_button=tk.Button(windows,text="Get Public IP",command=get_public_ip)
get_ip_button.pack()

download_label = tk.Label(windows, text="Download Speed: N/A Mbps\n")
download_label.pack()

upload_label = tk.Label(windows, text="Upload Speed: N/A Mbps\n")
upload_label.pack()

speed_test_button = tk.Button(windows, text="Run Speed Test", command=update_speed_labels)
speed_test_button.pack()

ping_status_label = tk.Label(windows, text="Network Status: N/A\n")
ping_status_label.pack()

ping_status_button = tk.Button(windows, text="Check Ping Status", command=check_ping)
ping_status_button.pack()


trace_label = tk.Label(windows, text="TraceRoute Result:\n")
trace_label.pack()


trace_button = tk.Button(windows, text="Run TraceRoute", command=TraceRoute)
trace_button.pack()


result_label = tk.Label(windows, text="OpenVPN TLS Verification Result:\n")
result_label.pack()

verify_tls_button = tk.Button(windows, text="Verify OpenVPN TLS", command=verify_openvpn_tls_and_display_result)
verify_tls_button.pack()

packet_loss_result = tk.Label(windows, text="Packet Loss Result:\n")
packet_loss_result.pack()

run_verify_no_packet_loss_button = tk.Button(windows, text="Run Verify No Packet Loss", command=run_verify_no_packet_loss)
run_verify_no_packet_loss_button.pack()

dns_leak_result = tk.Label(windows, text="RESULT OF DNS LEAK TESTING:\n")
dns_leak_result.pack()

dns_leak_result_button = tk.Button(windows, text="RUN DNS Leak Test", command=perform_dns_leak_test)
dns_leak_result_button.pack()

windows.mainloop()