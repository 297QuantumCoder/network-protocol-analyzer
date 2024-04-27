
# Network Protocol Analyzer

## Overview

The Network Protocol Analyzer is a Python-based tool designed for analyzing network packets to extract and display information about various protocols such as HTTP, DNS, TCP, and UDP. This project aims to provide a user-friendly interface for capturing, parsing, and analyzing network packets, making it an ideal tool for students and professionals interested in network security, protocol analysis, and cybersecurity research.

## Features

- **Packet Capture**: Capture network packets in real-time using the `scapy` library.
- **Protocol Parsing**: Analyze packets to extract information about various protocols including TCP, UDP, and IP.
- **User-Friendly Interface**: Intuitive GUI built using Tkinter for easy interaction and data visualization.
- **Packet Logging**: Save extracted packet information to a text file for future reference and analysis.
- **Cross-Platform Compatibility**: Works on both Unix-like and Windows operating systems.

## Installation

1. Clone the repository:

```bash
git clone https://github.com/297QuantumCoder/network-protocol-analyzer
```

2. Run the application:

```bash
python main.py
```

## Usage

1. Start the application by running `main.py`.
2. Click on the "Start" button to begin packet capture and analysis.
3. Analyzed packet information will be displayed in the GUI.
4. Click on the "Stop" button to stop packet capture.
5. Use the "Clear" button to clear the displayed packets.
6. Extracted packet information is saved to a text file named `packet_log.txt` in the project directory.

## Contributing

Contributions are welcome! Please follow these steps to contribute:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/new-feature`).
3. Make your changes.
4. Commit your changes (`git commit -am 'Add new feature'`).
5. Push to the branch (`git push origin feature/new-feature`).
6. Create a new Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
```
