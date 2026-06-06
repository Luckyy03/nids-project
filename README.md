<img width="1802" height="651" alt="image" src="https://github.com/user-attachments/assets/331bd761-e812-44b7-b5c6-870c3428d5be" />


# Network Intrusion Detection System (NIDS)

A real-time network intrusion detection system built with Python and Scapy.
Detects live network attacks using both rule-based logic and a Machine Learning
classifier trained on the NSL-KDD benchmark dataset.

## Features
- Live packet capture on any network interface
- Detects: Port Scans, SYN Floods, DNS Tunneling
- Random Forest ML model (99%+ accuracy on NSL-KDD)
- Real-time Rich terminal dashboard
- JSON incident logging for every alert

## Tech Stack
Python | Scapy | Scikit-learn | Pandas | Rich | Wireshark/PCAP

## Quick Start
```bash
git clone https://github.com/YOUR_USERNAME/nids-project
cd nids-project
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 src/ml_classifier.py   # Train model (~2 min)
sudo venv/bin/python3 main.py  # Start NIDS
```

## Detection Logic
| Attack | Method | Threshold |
|--------|--------|-----------|
| Port Scan | 15+ unique ports / 10s | Rule-based |
| SYN Flood | 100+ SYN packets / 10s | Rule-based |
| DNS Tunneling | 30+ DNS queries / 10s or query > 50 chars | Rule-based |
| General attacks | Random Forest on 41 network features | ML — 99% accuracy |

## Dataset
NSL-KDD (125,973 training samples, 22,544 test samples)

## Author
Muhammad Luqman Ijaz — github.com/Luckyy03
