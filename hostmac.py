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
    if inputIP.count(".") != 3:
        return False
    try:
        first = inputIP.split(".")[0]
        second = inputIP.split(".")[1]
        third = inputIP.split(".")[2]
        fourth = inputIP.split(".")[3]
        octets = [first, second, third, fourth]
    except IndexError:
        return False
    for i in octets:
        if len(i) < 1:
            return False
        if len(i) > 3:
            return False
        else:
            pass
        try:
            int(i)
        except ValueError:
            return False
    return True

#returns hostname given IP
def nslooky(ip):
    try: 
        output = socket.gethostbyaddr(ip)
        return output[0]
    except: 
        output = "No host name found" 
        return output

#creates titles in .csv output file
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

#returns ping results
def getPing(ip):
    if os.name == 'nt':  # Windows
        pingText = "ping -n 1 " + ip
    elif os.name =='posix':  # Linux
        pingText = "ping -c 1 " + ip
    ping = subprocess.Popen(pingText, shell=True, stdout=subprocess.PIPE)
    pingResult = ping.communicate()
    if os.name == 'nt':  # Windows
        try:
            if pingResult[0].split("\n")[1].startswith("Pinging"):
                subPing = pingResult[0].split("\n")[1]
                subPing = subPing.split()
                subPing = subPing[0] + " " + subPing[1]
            if pingResult[0].split("\n")[0].startswith("Ping request could not"):
                subPing = pingResult[0].split("\n")[0].split()[6][:-1] + " Ping-no host found"
                #subPing = "Ping-no host found"
        except:
            subPing = "General except error in getPing()"
    elif os.name == 'posix':  # Linux
        ping_found = re.search(r'time=(.*\sms)?', pingResult[0])
        if ping_found:
            subPing = ping_found.group(1)
        else:
            subPing = 'Host Unreachable'
    print subPing,
    return subPing

#returns name results
def getName(ip):
    try:
        name = nslooky(ip)
        name = name.split(".")[0]
    except:
        name = "General except error in getName()"
    print name,
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
                print item,
            if arpResult[0].split("\n")[1].startswith("Interface:"):
                item = arpResult[0].split("\n")[-2]
                item = item.split()[1]
                print item,
            if arpResult[1] == None:
                item = "ARP-bad argument"
                print item,
        except IndexError:
            if arpResult[1].startswith("ARP: bad argument"):
                item = "ARP: bad argument"
                print item,
        except:
            item = "General except error in getMac()"
            print item,
    if os.name == 'posix':  # Linux
        find_mac = re.search(r'\s(([0-9A-F]{2}[:-]){5}([0-9A-F]{2}))?\s',
                             arpResult[0].upper())
        if find_mac:
            item = find_mac.group(1)
        else:
            item = 'No MAC Found'
        print item
    return item

def getOne(ip):
    print
    try:
        myfile = open("./output/ip.csv", "ab+")
    except IOError as (errno, strerror):
        print "Could not open /output/ip.csv: I/O error({0}): {1}".format(errno, strerror)
        sys.exit()
    wr = csv.writer(myfile)
    ping = getPing(ip)
    name = getName(ip)
    mac = getMac(ip)
    csvOut = [ip, name, mac]
    wr.writerow(csvOut)
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
        print
        ip = firstThree + last
        ping = getPing(ip)
        name = getName(ip)
        mac = getMac(ip)
        csvOut = [ip, name, mac]
        wr.writerow(csvOut)
        last = str(int(last) + 1)
    myfile.close()

myIP = ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][0])


while True:
    print
    print "Detected IP: " + myIP
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
            getAll(myIP)
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
