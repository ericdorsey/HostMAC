# hostmac.py

### Description:

When run, user has two available options: 

* Attempts detection of host IP address, then iterates through subnet current host is on ```(x.x.x.1 - x.x.x.254)``` and outputs:
  *  IP Address, ping ```ms``` response time, Hostname and MAC address for each device found
 
* Enter any IP address (in subnet range host is part of), and output (for that device):
  * IP Address, ping ```ms``` response time, Hostname and MAC address
 

* Results are written to ```/YYYY-MM-DD_output/ip.csv```

___

### Tested in:

OS | Python Version
--- | ---
Fedora 21 | 2.7.8
Fedora 21 | 3.4.1
CentOS 6.6 | 2.6.6
CentoOS 7.0 | 2.7.5
Ubuntu 14.10 | 2.7.8
Windows 8 | 2.7.9 
Windows 7 | 2.7.2
Ubuntu 14.04.2 LTS | 2.7.6
OSX 10.10.2 | 2.7.6

### Limitations:

IPv4 compatible only.    

___
[![https://www.python.org/](https://www.python.org/static/community_logos/python-powered-w-100x40.png)](https://www.python.org/)
