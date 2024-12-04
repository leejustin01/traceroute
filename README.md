# traceroute

This is a traceroute CLI tool that builds upon a ICMP ping implementation provided by CS 372 at Oregon State University.

Traceroute is a computer networking diagnostic tool that allows a user to trace the route from a host running the traceroute program to any other host in the world. Traceroute is implemented with ICMP messages. It works by sending ICMP echo (ICMP type ‘8’) messages to the same destination with increasing time-to-live (TTL) field value. The routers along the traceroute path return ICMP Time Exceeded (ICMP type ‘11’ ) when the TTL field becomes zero. The final destination sends an ICMP reply (ICMP type ’0’ ) message on receiving the ICMP echo request. The IP addresses of the routers which send replies can be extracted from the received packets. The round-trip time between the sending host and a router is determined by setting a timer at the sending host.

# Usage
The program is currently set to run traceroute to 8.8.8.8
Change the function call in main to your desired URL or IP address.
```python
def main():
    icmpHelperPing = IcmpHelperLibrary()
    icmpHelperPing.traceRoute("URL or IP address")
```

Run the traceroute program with python3.
```bash
python3 traceroute.py
```
Please Note:
  - This program will not work for websites that block ICMP traffic.
  - You may have to turn your firewall or antivirus software off to allow the messages to be sent and received.
  - This program requires the use of raw sockets. In some operating systems, you may need administrator/root privileges to be able to run the traceroute program.
    - On Linux-based systems, the command will look something like this:
```bash
sudo python3 ICMPHelperLibrary.py
```

