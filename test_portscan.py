"""
Port scan simulation for testing anomaly detection.
Connects to multiple ports on the target with a small delay so cicflowmeter
has time to register each flow before the next one starts.
"""
import socket
import time
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.1"
PORTS = [21, 22, 23, 25, 53, 110, 139, 445, 3306, 3389, 5900, 8080]
DELAY = 0.3  # seconds between connections

print(f"Scanning {TARGET} on {len(PORTS)} ports...")
for port in PORTS:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((TARGET, port))
        status = "open" if result == 0 else "closed"
        print(f"  {port}/tcp {status}")
        s.close()
    except Exception as e:
        print(f"  {port}/tcp error: {e}")
    time.sleep(DELAY)

print("Done. Check the dashboard for alerts.")
