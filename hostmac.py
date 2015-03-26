#!/usr/bin/env python
import socket
import os
import subprocess
import csv
import sys
import re
import time
import argparse

# Override builtin: raw_input was renamed to input in python3 (PEP 3111)
try:
    input = raw_input
except NameError:
    pass


def create_output_folder_name():
    """
    Returns the output folder name in format YYYY-MM-DD_output
    :return:
    """
    date_today = time.strftime("%Y-%m-%d")
    folder_name = "%s_output" % date_today
    return folder_name


def create_csv_file_name():
    """
    Returns the CSV file name in format Hr_Min_{AM/PM}.csv
    :return:
    """
    time_now = time.strftime("%I_%M_%p")
    csv_file_name = "%s.csv" % time_now
    if csv_file_name[0] == "0": # strip leading zero off
        csv_file_name = csv_file_name.lstrip('0')
    return csv_file_name

# Create the output folder name
folder_name = create_output_folder_name()

# Create the CSV file name
csv_file_name = create_csv_file_name()


def detect_os():
    """
    Detects OS of system and sets os commands for use in various functions.
    :return: dict()
    """
    os_info = {}
    if os.name == 'nt':  # Windows
        os_info['os'] = "win"
        os_info['arp_cmd'] = "arp -a {ip}"
        os_info['ping_cmd'] = "ping -n 1 {ip}"
    if os.name == 'posix':  # posix
        os_info['os'] = "posix"
        os_info['arp_cmd'] = "arp -a | grep -w {ip}"
        os_info['ping_cmd'] = "ping -c 1 {ip}"
    # check for OSX last because it also shows up as posix in os.name
    if sys.platform == 'darwin':  # OSX
        os_info['os'] = "osx"
        os_info['arp_cmd'] = "arp -a | grep -w {ip}"
        os_info['ping_cmd'] = "ping -c 1 {ip}"
    return os_info

detected_os = detect_os()

# Creates the output directory
def make_dir(folder_name):
    # Only create output folder if it doesn't exist yet
    if not os.path.exists("./%s" % folder_name):
        try:
            os.makedirs("./%s" % folder_name)
            print("Created output folder /%s" % folder_name)
        except OSError as err:
            print("Unable to create folder /%s" % folder_name)
            exists_error = re.search("exists", str(err))
            if exists_error: # in theory we should never trigger this
                print("Reason: Folder already exists.")
            perms_error = re.search("denied", str(err))
            if perms_error:
                print("Reason: Insufficient permissions.")
            if not exists_error and not perms_error:
                print("Encountered error while creating output folder:")
                print(err)

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
def nslooky(ip, detected_os):
    try:
        output = socket.gethostbyaddr(ip)
        return output[0]
    except Exception as err:
        if detected_os['os'] == 'osx':
            output = subprocess.Popen("smbutil status %s | grep Server" % ip, shell=True, stdout=subprocess.PIPE)
            output = output.communicate()
            if output[0] == "":
                output = "No hostname found"
                return output
            output = output[0].split(' ')[1].strip()
            return output
        not_found_error = re.search("not found", str(err))
        if not_found_error: # Win, catch [Errno 11004] host not found
            output = "No hostname found"
        else:
            output = "No hostname found"
        return output

# Returns name of pinged host
def getName(ip):
    try:
        name = nslooky(ip, detected_os)
    except Exception as err: # We shouldn't ever hit this, should catch this in nslooky()
        name = "Gen. except error in getName()"
    return name


# Creates titles (headers) in .csv output file
def titleCheck(folder_name, csv_file_name):
    exists = os.path.exists(r"./%s/%s" % (folder_name, csv_file_name))
    if exists == True:
        pass
    if exists == False:
        make_dir(folder_name)
        myfile = open("./%s/%s" % (folder_name, csv_file_name), "w")
        wr = csv.writer(myfile)
        titles = ["ip", "ping ms time", "hostname", "mac"]
        wr.writerow(titles)

# Returns ping ms response time of pinged host
def getPing_msResponse(ip, detected_os):
    ping = subprocess.Popen(detected_os['ping_cmd'].format(ip=ip), shell=True, stdout=subprocess.PIPE)
    pingResult = ping.communicate()
    ping_found = re.search(r'time[=<]?(\d*[\.]?\d*\s?ms)?', str(pingResult[0]))
    if ping_found and ping_found.group(1):
        ping_msResponse = ping_found.group(1)
    else:
        ping_msResponse = 'Host unreachable'
    return ping_msResponse

# Given an IP, returns MAC results
def getMac(ip, detected_os):
    def subprocArp(arpText):
        arp = subprocess.Popen(arpText, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        arp = arp.communicate()
        return arp
    arpResult = subprocArp(detected_os['arp_cmd'].format(ip=ip))
    find_mac = re.search(r'[\b\s]*(([0-9A-F]{2}[:-]){5}([0-9A-F]{2}))[\b\s]*',
                         str(arpResult[0].upper()))
    if find_mac:
        item = re.sub('-', ':', find_mac.group(1))
    else:
        item = 'No MAC addr. found'
    return item


def get_results(ip, folder_name, csv_file_name,
                start=1, end=255, get_all=False, csv_out=False):
    if csv_out:
        try:
            myfile = open("./%s/%s" % (folder_name, csv_file_name), "a")
            wr = csv.writer(myfile)
        except IOError as e:
            print("Could not open /{2}/{3}: I/O error({0}): {1}".format(
                  e.errno, e.strerror, folder_name, csv_file_name))
            sys.exit()
    print("\nResults:")
    if get_all:
        first_three = re.match(r'((\d{,3}\.\d{,3}\.\d{,3})\.)?(\d{,3})', ip)
        if int(end) <= 254:
            end += 1
        for address in range(int(start), int(end)):
            ip = first_three.group(1) + str(address)
            ping = getPing_msResponse(ip, detected_os)
            name = getName(ip)
            mac = getMac(ip, detected_os)
            if csv_out:
                wr.writerow([ip, ping, name, mac])
            print("%s %s %s %s" % (ip, ping, name, mac))
    else:
        ping = getPing_msResponse(ip, detected_os)
        name = getName(ip)
        mac = getMac(ip, detected_os)
        if csv_out:
            wr.writerow([ip, ping, name, mac])
        print("%s %s %s %s" % (ip, ping, name, mac))
    if csv_out:
        myfile.close()


def detect_ip(ip_address=None):
    """ Create a UDP socket connection to populate getsockname()
    The address does not actually need to resolve ie:
    Google DNS 8.8.8.8 used here
    :param ip_address:
    :return:
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip_address = s.getsockname()[0]
    except socket.error:
        print("Failed to detect IP of current host!")
        choice = input("(I)nput host IP manually, or (Q)uit?: ")
        if choice.upper() == "I":
            while True:
                if not ip_address or not ipCheck(ip_address):
                    ip_address = input("INPUT IP: ")
                else:
                    break
        else:
            sys.exit("\nQuitting..")
    finally:
        s.close()
    return ip_address


def main(ip=None, start=1, end=255, get_all=False, csv_out=False):
    answer = int()
    ip_range = sorted([int(start), int(end)])  # ensure range from low to high
    while answer != 3:
        print('\n\nQuery based on IP: %s\n'
              '1) Continue with detected IP (entries for x.x.x.%s-%s)\n'
              '2) Enter another IP (creates one entry)\n'
              '3) Exit' % (ip, ip_range[0], int(ip_range[1])))
        try:
            if get_all:
                answer = 1
            else:
                answer = int(input("Selection? "))
            if answer == 1:
                get_all = True
                print('\n')
                if csv_out:
                    titleCheck(folder_name, csv_file_name)
                get_results(ip, folder_name, csv_file_name,
                            end=ip_range[1], start=ip_range[0],
                            get_all=get_all, csv_out=csv_out)
                get_all = False  # Clear the get_all flag to break loop
            elif answer == 2:
                choiceIP = input("Input IP: ")
                if ipCheck(choiceIP):
                    if csv_out:
                        titleCheck(folder_name, csv_file_name)
                    get_results(choiceIP, folder_name, csv_file_name,
                                start=ip_range[0], end=ip_range[1],
                                get_all=get_all, csv_out=csv_out)
                else:
                    print("Invalid IP")
            elif answer == 3:
                sys.exit()
        except ValueError:
            print("\n")
            print("Invalid entry")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HostMAC")
    parser.add_argument('-csv', help='log output to csv', action='store_true',
                        required=False)
    parser.add_argument('-ip', default=detect_ip(),
                        help='specify ip, default: current ip', required=False)
    parser.add_argument('-all', help='check range 1-254', action='store_true',
                        required=False)
    parser.add_argument('-start', default=1, type=int, choices=range(1, 254),
                        metavar='', help='start of range', required=False)
    parser.add_argument('-end', default=255, type=int, choices=range(2, 255),
                        metavar='', help='end of range', required=False)
    args = parser.parse_args()
    try:
        main(ip=args.ip, start=args.start, end=args.end,
             get_all=args.all, csv_out=args.csv)
    except KeyboardInterrupt:
        print("\nCanceled by user.. Exiting.")
