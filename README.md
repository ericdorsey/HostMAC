### hostmac.py

**Description:**
When run, user has two options: 

* Detect host IP address, then iterate through subnet current host is on (xxx.xxx.xxx.1 - xxx.xxx.xxx.255) and outputs IP Address, Host Name and MAC address for each PC / device found. 
* Asks user to input any IP address (within current subnet) and outputs Host Name and MAC address for that IP address. 

Results are written to /output/ip.csv

**Requirements:** 
Python 2.7

**Limitations:**
HostMAC is meant to be run from a Windows client, as the program parses text returned from `ARP -A` commands in a Windows command prompt (cmd.exe). In other words, do not run it from a Linux or OSX box. IPv4 compatible only. 
