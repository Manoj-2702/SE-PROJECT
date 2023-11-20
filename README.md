# OpenVPN configuration and connectivity test

This script is designed to perform various network-related tests, including checking the public IP, running a speed test, checking ping status, conducting a trace route, verifying OpenVPN TLS configuration, checking for packet loss, and performing a DNS leak test.

## Features

- Get the public IP address using an external API.
- Run a speed test to measure download and upload speeds.
- Check the ping status to verify network connectivity.
- Perform a trace route to analyze the route to a destination.
- Verify OpenVPN TLS configuration and display the result.
- Check for packet loss using the ping command.
- Conduct a DNS leak test to identify potential leaks.

## Prerequisites

- Python 3.x installed.
- Required Python libraries installed (requests, speedtest, tkinter, json, os, subprocess, termcolor, cryptography, scapy, dotenv).

## Configuration

1. Clone this repository:

   ```bash
   git clone https://github.com/Manoj-2702/SE-Project.git
   cd SE Project
   ```

2. Install the required Python libraries:

   ```bash
   pip install -r requirements.txt
   ```

3. Create a `.env` file with the following variables:

   ```env
   DESTINATION_HOST="google.com"
   CONFIG_PATH=path/to/openvpn/config.ovpn
   API_ENDPOINT=https://api.ipify.org?format=json
   ```

   Adjust the values accordingly.

## Usage

1. Run the script:

   ```bash
   python main3.py
   ```

2. Follow the instructions in the Tkinter GUI to perform various network tests.

## License

This project is licensed under the [MIT License](LICENSE).

## Acknowledgments

- [Speedtest by Ookla](https://www.speedtest.net/)
- [Ipify API](https://www.ipify.org/)
- [Cryptography Library](https://cryptography.io/)
- [Scapy](https://scapy.net/)
- [dotenv](https://pypi.org/project/python-dotenv/)
- [Requests](https://docs.python-requests.org/en/latest/)

Feel free to contribute or report issues!
