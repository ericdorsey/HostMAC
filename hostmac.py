import socket
import os
import subprocess
import csv
import sys
import re

# Creates the /output directory
def makeDir():
    try:
        os.makedirs("./output")
    except OSError:
        pass

# Verifies correct format of IP xxx.xxx.xxx.xxx
def ipCheck(inputIP):
    ipregex = '\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.)' \
              '{3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b'
    validIP = re.match(ipregex, inputIP)
    if validIP:
        return True
    else:
        return False

# Given an IP, returns hostname
def nslooky(ip):
    try:
        output = socket.gethostbyaddr(ip)
        return output[0]
    except:
        if sys.platform == 'darwin': # OSX
            output = subprocess.Popen("smbutil status %s | grep Server" % ip, shell=True, stdout=subprocess.PIPE)
            output = output.communicate()
            if output[0] == "":
                output = "No hostname found"
                return output
            output = output[0].split(' ')[1].strip()
            return output
        else:
            output = "No hostname found"
            return output

# Creates titles (headers) in .csv output file
def titleCheck():
    exists = os.path.exists(r"./output/ip.csv")
    if exists == True:
        pass
    if exists == False:
        makeDir()
        myfile = open("./output/ip.csv", "ab+")
        wr = csv.writer(myfile)
        titles = ["ip", "ping ms time", "hostname", "mac"]
        wr.writerow(titles)

# Returns ping ms response time of pinged host
def getPing_msResponse(ip):
    if os.name == 'nt':  # Windows
        pingText = "ping -n 1 " + ip
    elif os.name =='posix':  # *nix or OSX
        pingText = "ping -c 1 " + ip
    ping = subprocess.Popen(pingText, shell=True, stdout=subprocess.PIPE)
    pingResult = ping.communicate()
    ping_found = re.search(r'time[=]?(\d*[\.]?\d*\s?ms)?', str(pingResult[0]))
    if ping_found:
        ping_msResponse = ping_found.group(1)
    else:
        ping_msResponse = 'Host unreachable'
    return ping_msResponse

# Returns name of pinged host
def getName(ip):
    try:
        name = nslooky(ip)
    except:
        name = "Gen. except error in getName()"
    return name

# Given an IP, returns MAC results
def getMac(ip):
    def subprocArp(arpText):
        arp = subprocess.Popen(arpText, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        arp = arp.communicate()
        return arp
    if os.name == 'nt':  # Windows
        arpResult = subprocArp("arp -a %s" % ip)
        try:
            if arpResult[0].startswith("No ARP"):
                item = "MAC not found, No ARP entry"
            if arpResult[0].split("\n")[1].startswith("Interface:"):
                item = arpResult[0].split("\n")[-2]
                item = item.split()[1]
                item = item.replace("-", ":").upper()
            if arpResult[1] == None:
                item = "ARP bad argument"
        except IndexError:
            if arpResult[1].startswith("ARP: bad argument"):
                item = "ARP bad argument"
        except:
            item = "Gen. except error in getMac()"
    if os.name == 'posix': # *nux or OSX
        arpResult = subprocArp("arp -a | grep -w %s" % ip)
        find_mac = re.search(r'\s(([0-9A-F]{2}[:-]){5}([0-9A-F]{2}))?\s',
                             arpResult[0].upper())
        if find_mac:
            item = find_mac.group(1)
        else:
            item = 'No MAC addr. found'
    return item

def getOne(ip):
    print
    try:
        myfile = open("./output/ip.csv", "ab+")
    except IOError as (errno, strerror):
        print "Could not open /output/ip.csv: I/O error({0}): {1}".format(errno, strerror)
        sys.exit()
    wr = csv.writer(myfile)
    ping = getPing_msResponse(ip)
    name = getName(ip)
    mac = getMac(ip)
    csvOut = [ip, ping, name, mac]
    wr.writerow(csvOut)
    print "%s %s %s %s" % (ip, ping, name, mac)
    myfile.close()

def getAll(ip):
    try:
        myfile = open("./output/ip.csv", "ab+")
    except IOError as (errno, strerror):
        print "Could not open /output/ip.csv: I/O error({0}): {1}".format(errno, strerror)
        sys.exit()
    wr = csv.writer(myfile)
    firstThree = ip.split(".")[0] + "." + ip.split(".")[1] + "." + ip.split(".")[2] + "."
    last = "1"
    while int(last) <= 254:
        ip = firstThree + last
        ping = getPing_msResponse(ip)
        name = getName(ip)
        mac = getMac(ip)
        csvOut = [ip, ping, name, mac]
        wr.writerow(csvOut)
        last = str(int(last) + 1)
        print "%s %s %s %s" % (ip, ping, name, mac)
    myfile.close()


def detect_ip(ip_address=None):
    """ Create a UDP socket connection to populate getsockname()
    The address does not actually need to resolve ie: 1.2.3.4
    :param ip_address:
    :return:
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('1.2.3.4', 0))
        ip_address = s.getsockname()[0]
    except socket.error:
        try:
            # OSX doesn't like port 0, use Google public DNS and port 80
            s.connect(('8.8.8.8', 80))
            ip_address = s.getsockname()[0]
        except socket.error:
            print("Failed to detect IP of current host!")
            choice = raw_input("(I)nput host IP manually, or (Q)uit?: ")
            if choice.upper() == "I":
                while True:
                    if not ip_address or not ipCheck(ip_address):
                        ip_address = raw_input("INPUT IP: ")
                    else:
                        break
            else:
                sys.exit("Quitting..")
    finally:
        s.close()
    return ip_address


while True:
    ip = detect_ip()
    print
    print "Detected IP: " + ip
    print
    print "1) Continue with detected IP (creates 254 entries)"
    print "2) Enter another IP (creates one entry)"
    print "3) Exit"
    print
    try:
        answer = int(raw_input("Selection? "))
        if answer == 1:
            print
            titleCheck()
            getAll(ip)
            sys.exit()
        elif answer == 2:
            print
            choiceIP = raw_input("Input IP: ")
            trueFalse = ipCheck(choiceIP)
            if trueFalse == True:
                titleCheck()
                getOne(choiceIP)
                sys.exit()
            if trueFalse == False:
                print
                print "Invalid IP"
        elif answer == 3:
            sys.exit()
    except ValueError:
        print
        print "Invalid entry"
