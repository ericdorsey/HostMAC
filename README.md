# hostmac.py

### Description

When run, user has two available options: 

* Attempts detection of host IP address, then iterates through subnet current host is on ```(x.x.x.1 - x.x.x.254)``` and outputs:
  *  IP Address, ping ```ms``` response time, Hostname and MAC address for each device found
 
* Enter any IP address (in subnet range host is part of), and output (for that device):
  * IP Address, ping ```ms``` response time, Hostname and MAC address
 

Results are optionally written to ```/YYYY-MM-DD_output/HH_mm_{AM/PM}.csv```

### Help

There are several command line flags available.

Linux / OSX:

```
$ ./hostmac.py -h
```

Windows:

```
C:\>python hostmac.py -h
```

### Tests

```
~/Code/HostMAC/tests $ python hostmac_test.py
...............
----------------------------------------------------------------------
Ran 15 tests in 1.207s

OK
```

### Compatibility:

OS | Python Version
--- | ---
Fedora 21 | 2.7.8
Fedora 21 | 3.4.1
CentoOS 7.0 | 2.7.5
Ubuntu 14.10 | 2.7.8
Windows 8 | 2.7.9
Windows 8 | 3.4.3
Windows 7 | 2.7.2
Ubuntu 14.04.2 LTS | 2.7.6
OSX 10.10.2 | 2.7.6

### Limitations:

* IPv4 compatible only. 
* `Class C` (`/24`) subnets only 
* Cygwin not supported.  

___
[![https://www.python.org/](https://www.python.org/static/community_logos/python-powered-w-100x40.png)](https://www.python.org/)
