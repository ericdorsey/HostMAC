import socket
import os
import subprocess
import csv
import sys
import re

#creates the /output directory
def makeDir():
    try:
        os.makedirs("./output")
    except OSError:
        pass

#verifies correct format of IP xxx.xxx.xxx.xxx
def ipCheck(inputIP):
    ipregex = '\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.)' \
              '{3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b'
    validIP = re.match(ipregex, inputIP)
    if validIP:
        return True
    else:
        return False

#returns hostname given IP
def nslooky(ip):
    try: 
        output = socket.gethostbyaddr(ip)
        return output[0]
    except: 
        output = "No host name found" 
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
        titles = ["ip", "hostname", "mac"]
        wr.writerow(titles)

# Returns ping ms resonse time of pinged host 
def getPing_msResponse(ip):
    if os.name == 'nt':  # Windows
        pingText = "ping -n 1 " + ip
    elif os.name =='posix':  # Linux
        pingText = "ping -c 1 " + ip
    ping = subprocess.Popen(pingText, shell=True, stdout=subprocess.PIPE)
    pingResult = ping.communicate()
    #print pingResult # Remove after
    if os.name == 'nt':  # Windows
        ping_found = re.search(r'time.*ms', pingResult[0])
        if ping_found:
            ping_msResponseFull = ping_found.group()
            ping_msResponse = ping_msResponseFull[5:]
            #ping_msResponse = ping_msResponse.lstrip("time<")
        else:
            ping_msResponse = 'Host Unreachable'
    elif os.name == 'posix':  # *nix or OSX
        ping_found = re.search(r'time=(.*\sms)?', pingResult[0])
        if ping_found:
            ping_msResponse = ping_found.group(1)
        else:
            ping_msResponse = 'Host Unreachable'
    #print "ping_msRepsonse in getPing_msResponse(): ", ping_msResponse # Debugging
    return ping_msResponse

# Returns name of pinged host
def getName(ip):
    try:
        name = nslooky(ip)
        name = name.split(".")[0]
    except:
        name = "General except error in getName()"
    #print name, #Debugging
    return name

#returns MAC results
def getMac(ip):
    arpText = "arp -a " + ip 
    arp = subprocess.Popen(arpText, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    arpResult = arp.communicate()
    if os.name == 'nt':  # Windows
        try:
            if arpResult[0].startswith("No ARP"):
                item = "MAC not found-No ARP entry"
                #print item,
            if arpResult[0].split("\n")[1].startswith("Interface:"):
                item = arpResult[0].split("\n")[-2]
                item = item.split()[1]
                item = item.replace("-", ":").upper()
                #print item,
            if arpResult[1] == None:
                item = "ARP-bad argument"
                #print item,
        except IndexError:
            if arpResult[1].startswith("ARP: bad argument"):
                item = "ARP: bad argument"
                #print item,
        except:
            item = "General except error in getMac()"
            #print item,
    if os.name == 'posix':  # Linux
        find_mac = re.search(r'\s(([0-9A-F]{2}[:-]){5}([0-9A-F]{2}))?\s',
                             arpResult[0].upper())
        if find_mac:
            item = find_mac.group(1)
        else:
            item = 'No MAC Found'
        #print item
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
        #print
        ip = firstThree + last
        ping = getPing_msResponse(ip)
        name = getName(ip)
        mac = getMac(ip)
        csvOut = [ip, ping, name, mac]
        wr.writerow(csvOut)
        last = str(int(last) + 1)
        print "%s %s %s %s" % (ip, ping, name, mac)
    myfile.close()


def detect_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('example.com', 0))
        ip_address = s.getsockname()[0]
    except socket.error:
        ip_address = '127.0.0.1'
    finally:
        s.close()
    return ip_address


while True:
    print
    print "Detected IP: " + detect_ip()
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
            getAll(detect_ip())
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
