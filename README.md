# hostmac.py

**Description:**  
When run, user has two available options: 

* Detect host IP address, then iterate through subnet current host is on (xxx.xxx.xxx.1 - xxx.xxx.xxx.255) and outputs:
  *  IP Address, Ping ```ms``` response time, Host Name and MAC address for each device found
 
* Or, asks user to input any IP address (within current subnet) and outputs Host Name and MAC address for that one IP address. 

Results are written to ```/output/ip.csv```

**Requirements:**   

* Python 2.6.x - 2.7.x ... ish.

**Limitations:**  

* IPv4 compatible only.    
* Not currently compatible with OSX

Tested by [@bcambl](https://github.com/bcambl) in:

* Fedora 21 (python 2.7.8)  
* CentOS 6.6 (python 2.6.6)  
* CentoOS 7.0 (python 2.7.5)  
* Ubuntu 14.10 (2.7.8)  
* Windows 8 (python 2.7.9)   

Tested by [@ericdorsey](https://github.com/ericdorsey) in:  

* Windows 7 (python 2.7.2)
* Ubuntu 14.04.2 LTS (python 2.7.6)
