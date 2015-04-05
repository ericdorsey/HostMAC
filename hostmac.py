#!/usr/bin/env python
import socket
import os
import subprocess
import csv
import sys
import re
import time
import argparse
import shlex

# Override builtin: raw_input was renamed to input in python3 (PEP 3111)
try:
    input = raw_input
except NameError:
    pass


def create_output_folder_name():
    """
    Return the output folder name in format YYYY-MM-DD_output.

    :return:
    """
    date_today = time.strftime("%Y-%m-%d")
    folder_name = "%s_output" % date_today
    return folder_name


def create_csv_file_name():
    """
    Return the CSV file name in format "Hr_Min_{AM/PM}.csv".

    :return:
    """
    time_now = time.strftime("%I_%M_%p")
    csv_file_name = "%s.csv" % time_now
    if csv_file_name[0] == "0":  # strip leading zero off
        csv_file_name = csv_file_name.lstrip('0')
    return csv_file_name

# Create the output folder name
folder_name = create_output_folder_name()

# Create the CSV file name
csv_file_name = create_csv_file_name()


def detect_os():
    """
    Detect OS of system and sets os commands for use in various functions.

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
        os_info['smbutil'] = "smbutil status {ip} | grep Server"
    return os_info

detected_os = detect_os()


def subproc_pipe_runner(ip, command):
    """
    Take an ip and a "raw" shell input command. Splits it on "|" if present,
    and runs it without dependency on shell=True.

    :param ip: The IP to run the command against
    :param command: The shell command to interpret. Max one pipe ("|")
    :return: string
    """
    command = command.replace("{ip}", "{0}")
    command = command.format(ip)

    #  Get both piped and unpiped commands into the same format:
    #  a list with one value
    if "|" in command:
        new_command = command.split("|")
    else:
        new_command = []
        new_command.append(command)

    if len(new_command) == 1:
        process_one = subprocess.\
            Popen(shlex.split("{0}".format(new_command[0])),
                  stdout=subprocess.PIPE)
        output = process_one.communicate()
        return output
    if len(new_command) == 2:
        process_one = subprocess.\
            Popen(shlex.split("{0}".format(new_command[0])),
                  stdout=subprocess.PIPE)
        process_two = subprocess.\
            Popen(shlex.split("{0}".format(new_command[1])),
                  stdin=process_one.stdout, stdout=subprocess.PIPE)
        process_one.stdout.close()
        output = process_two.communicate()
        return output


def make_dir(folder_name):
    """
    Create the output folder name if it doesn't exist yet.

    :param folder_name:
    :return:
    """
    if not os.path.exists("./%s" % folder_name):
        try:
            os.makedirs("./%s" % folder_name)
            print("Created output folder /%s" % folder_name)
        except OSError as err:
            print("Unable to create folder /%s" % folder_name)
            exists_error = re.search("exists", str(err))
            if exists_error:  # in theory we should never trigger this
                print("Reason: Folder already exists.")
            perms_error = re.search("denied", str(err))
            if perms_error:
                print("Reason: Insufficient permissions.")
            if not exists_error and not perms_error:
                print("Encountered error while creating output folder:")
                print(err)


def ip_check(input_ip):
    """
    Verify correct format of input_ip: "xxx.xxx.xxx.xxx".

    :param input_ip: string
    :return:
    """
    ipregex = '\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.)' \
              '{3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b'
    validIP = re.match(ipregex, input_ip)
    if validIP:
        return True
    else:
        return False


def nslooky(ip, detected_os):
    """
    Given an IP, returns hostname.

    :param ip: string
    :param detected_os: dict()
    :return: string
    """
    try:
        output = socket.gethostbyaddr(ip)
        return output[0]
    except Exception as err:
        if detected_os['os'] == 'osx':
            output = subproc_pipe_runner(ip, detected_os["smbutil"])
            if output[0] == "":
                output = "No hostname found"
                return output
            output = output[0].split(' ')[1].strip()
            return output
        not_found_error = re.search("not found", str(err))
        if not_found_error:  # Windows: catch [Errno 11004] host not found
            output = "No hostname found"
        else:
            output = "No hostname found"
        return output


def get_name(ip):
    """
    Return the name of pinged host.

    :param ip: string
    :return: string
    """
    try:
        name = nslooky(ip, detected_os)
    # We shouldn't ever hit this, should catch this in nslooky()
    except Exception as err:
        name = "Gen. except error in get_name()"
    return name


def title_check(folder_name, csv_file_name):
    """
    Create titles (headers) in .csv output file.

    :param folder_name: string
    :param csv_file_name: string
    :return:
    """
    exists = os.path.exists(r"./{0}/{1}".format(folder_name, csv_file_name))
    if exists is True:
        pass
    if exists is False:
        make_dir(folder_name)
        myfile = open("./{0}/{1}".format(folder_name, csv_file_name), "w")
        wr = csv.writer(myfile)
        titles = ["ip", "ping ms time", "hostname", "mac"]
        wr.writerow(titles)


def get_ping_ms_response(ip, detected_os):
    """
    Return ping ms response time of pinged host.

    :param ip: string
    :param detected_os: dict()
    :return:
    """
    pingResult = subproc_pipe_runner(ip, detected_os['ping_cmd'])
    ping_found = re.search(r'time[=<]?(\d*[\.]?\d*\s?ms)?', str(pingResult[0]))
    if ping_found and ping_found.group(1):
        ping_msResponse = ping_found.group(1)
    else:
        ping_msResponse = 'Host unreachable'
    return ping_msResponse


def get_mac(ip, detected_os):
    """
    Given an IP, return a MAC address.

    :param ip: string
    :param detected_os: string
    :return: string
    """
    arpResult = subproc_pipe_runner(ip, detected_os['arp_cmd'])
    find_mac = re.search(r'[\b\s]*(([0-9A-F]{2}[:-]){5}([0-9A-F]{2}))[\b\s]*',
                         str(arpResult[0].upper()))
    if find_mac:
        item = re.sub('-', ':', find_mac.group(1))
    else:
        item = 'No MAC addr. found'
    return item


def get_results(ip, folder_name, csv_file_name,
                start=1, end=255, get_all=False, csv_out=False):
    """
    Given inputs, get and display query results to end user.
    Writes CSV if applicable.

    :param ip: string
    :param folder_name: string
    :param csv_file_name: string
    :param start: int
    :param end: int
    :param get_all: boolean
    :param csv_out: boolean
    :return:
    """
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
            ping = get_ping_ms_response(ip, detected_os)
            name = get_name(ip)
            mac = get_mac(ip, detected_os)
            if csv_out:
                wr.writerow([ip, ping, name, mac])
            print("{0} {1} {2} {3}".format(ip, ping, name, mac))
    else:
        ping = get_ping_ms_response(ip, detected_os)
        name = get_name(ip)
        mac = get_mac(ip, detected_os)
        if csv_out:
            wr.writerow([ip, ping, name, mac])
        print("{0} {1} {2} {3}".format(ip, ping, name, mac))
    if csv_out:
        myfile.close()


def detect_ip(ip_address=None):
    """
    Create a UDP socket connection to populate getsockname().
    The address does not actually need to resolve ie:
    Google DNS 8.8.8.8 used here.

    :param ip_address: string
    :return: string
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
                if not ip_address or not ip_check(ip_address):
                    ip_address = input("INPUT IP: ")
                else:
                    break
        else:
            sys.exit("\nQuitting..")
    finally:
        s.close()
    return ip_address


def main(ip=None, start=1, end=255, get_all=False, csv_out=False):
    """
    Main program body.

    :param ip: string
    :param start: int
    :param end: int
    :param get_all: boolean
    :param csv_out: boolean
    :return:
    """
    answer = int()
    ip_range = sorted([int(start), int(end)])  # ensure range from low to high
    while answer != 3:
        print('\n\nQuery based on IP: {0}\n'
              '1) Continue with detected IP (entries for x.x.x.{1}-{2})\n'
              '2) Enter another IP (creates one entry)\n'
              '3) Exit'.format(ip, ip_range[0], int(ip_range[1])))
        try:
            if get_all:
                answer = 1
            else:
                answer = int(input("Selection? "))
            if answer == 1:
                get_all = True
                print('\n')
                if csv_out:
                    title_check(folder_name, csv_file_name)
                get_results(ip, folder_name, csv_file_name,
                            end=ip_range[1], start=ip_range[0],
                            get_all=get_all, csv_out=csv_out)
                get_all = False  # Clear the get_all flag to break loop
            elif answer == 2:
                choiceIP = input("Input IP: ")
                if ip_check(choiceIP):
                    if csv_out:
                        title_check(folder_name, csv_file_name)
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
