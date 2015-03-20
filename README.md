# hostmac.py

**Description:**  
When run, user has two available options: 

* Detect host IP address, then iterate through subnet current host is on (x.x.x.1-x.x.x.254) and outputs:
  *  IP Address, ping ```ms``` response time, Hostname and MAC address for each device found
 
* Enter any IP address, will output (for that device):
  * IP Address, ping ```ms``` response time, Hostname and MAC address
 

* Results are written to ```/output/ip.csv```

___

**Requirements:**   

* Python 2.6.x - 2.7.x ... ish.

**Limitations:**  

* IPv4 compatible only.    
___

Tested by [@bcambl](https://github.com/bcambl) in:

* Fedora 21 (python 2.7.8)  
* Fedora 21 (python 3.4.1)
* CentOS 6.6 (python 2.6.6)  
* CentoOS 7.0 (python 2.7.5)  
* Ubuntu 14.10 (2.7.8)  
* Windows 8 (python 2.7.9)   

Tested by [@ericdorsey](https://github.com/ericdorsey) in:  

* Windows 7 (python 2.7.2)
* Ubuntu 14.04.2 LTS (python 2.7.6)
* OSX 10.10.2 (python 2.7.6)

___
[![https://www.python.org/](https://www.python.org/static/community_logos/python-powered-w-100x40.png)](https://www.python.org/)
