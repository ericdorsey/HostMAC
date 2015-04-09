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

    :return: string
    """
    date_today = time.strftime("%Y-%m-%d")
    folder_name = "%s_output" % date_today
    return folder_name


def create_csv_file_name():
    """
    Return the CSV file name in format "Hr_Min_{AM/PM}.csv".

    :return: string
    """
    time_now = time.strftime("%I_%M_%p")
    csv_file_name = "%s.csv" % time_now
    if csv_file_name[0] == "0":  # strip leading zero off
        csv_file_name = csv_file_name.lstrip("0")
    return csv_file_name

# Create the output folder name
folder_name = create_output_folder_name()

# Create the CSV file name
csv_file_name = create_csv_file_name()


def detect_os():
    """
    Detect OS of system and sets OS commands for use in various functions.

    :return: dict()
    """
    os_info = {}
    if os.name == "nt":  # Windows
        os_info["os"] = "win"
        os_info["arp_cmd"] = "arp -a {ip}"
        os_info["ping_cmd"] = "ping -n 1 {ip}"
    if os.name == "posix":  # posix
        os_info["os"] = "posix"
        os_info["arp_cmd"] = "arp -a | grep -w {ip}"
        os_info["ping_cmd"] = "ping -c 1 {ip}"
    # check for OSX last because it also shows up as posix in os.name
    if sys.platform == "darwin":  # OSX
        os_info["os"] = "osx"
        os_info["arp_cmd"] = "arp -a | grep -w {ip}"
        os_info["ping_cmd"] = "ping -c 1 {ip}"
        os_info["smbutil"] = "smbutil status {ip} | grep Server"
    return os_info

# Set OS information
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
    :return: None
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
    :return: boolean
    """
    ipregex = "\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.)" \
              "{3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b"
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
    output_options = {
        "nohost" : "No hostname found",
        "unkhost" : "Unknown host"
    }
    try:
        output = socket.gethostbyaddr(ip)
        return output[0]
    except Exception as err:
        if detected_os["os"] == "osx":
            output = subproc_pipe_runner(ip, detected_os["smbutil"])
            output = output[0].decode("utf-8")  # Decode for Python3
            if output == "":
                output = output_options["nohost"]
                return output
            output = output.split(" ")[1].strip()
            return output
        not_found_error = re.search("not found", str(err))
        if not_found_error:  # Catch [Errno 11004] host not found
            output = output_options["nohost"]
        else:
            output = output_options["nohost"]
        unknown_host_error = re.search("Unknown host", str(err))
        if unknown_host_error:  # Catch [Errno 1] Unknown host
            output = output_options["unkhost"]
        return output


def title_check(folder_name, csv_file_name):
    """
    Create titles (headers) in .csv output file.

    :param folder_name: string
    :param csv_file_name: string
    :return: None
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
    :return: string
    """
    ping_result = subproc_pipe_runner(ip, detected_os["ping_cmd"])
    ping_found = re.search(r"time[=<]?(\d*[\.]?\d*\s?ms)?", str(ping_result[0]))
    if not ping_found:
        ping_ms_response = "Host unreachable"
    elif ping_found and ping_found.group(1):
        ping_ms_response = ping_found.group(1)
    else:
        ping_ms_response = "Host unreachable"
    return ping_ms_response


def get_mac(ip, detected_os):
    """
    Given an IP, return a MAC address.

    :param ip: string
    :param detected_os: string
    :return: string
    """
    arpResult = subproc_pipe_runner(ip, detected_os["arp_cmd"])
    find_mac = re.search(r"[\b\s]*(([0-9A-F]{2}[:-]){5}([0-9A-F]{2}))[\b\s]*",
                         str(arpResult[0].upper()))
    if find_mac:
        item = re.sub("-", ":", find_mac.group(1))
    else:
        item = "No MAC addr. found"
    return item


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
        s.connect(("8.8.8.8", 80))
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


def get_results(ip, folder_name, csv_file_name,
                start=1, end=255, csv_out=False, one_entry=False):
    """
    Given inputs, get and display query results to end user.
    Writes CSV if applicable.

    :param ip: string
    :param folder_name: string
    :param csv_file_name: string
    :param start: int
    :param end: int
    :param csv_out: boolean
    :return: None
    """
    def print_it(ip, ping, name, mac):
        print("{0:<16} {1:<17} {2:<18} {3:<18}".format(ip, ping, name, mac))
    if csv_out:
        try:
            myfile = open("./%s/%s" % (folder_name, csv_file_name), "a")
            wr = csv.writer(myfile)
        except IOError as e:
            print("Could not open /{2}/{3}: I/O error({0}): {1}".format(
                  e.errno, e.strerror, folder_name, csv_file_name))
            sys.exit()
    print("\nResults:")
    first_three = re.match(r"((\d{,3}\.\d{,3}\.\d{,3})\.)?(\d{,3})", ip)

    if int(end) <= 254:
        end += 1
    if one_entry:
        ping = get_ping_ms_response(ip, detected_os)
        name = nslooky(ip, detected_os)
        mac = get_mac(ip, detected_os)
        if csv_out:
            wr.writerow([ip, ping, name, mac])
        print_it(ip, ping, name, mac)
    else:  # More than one entry
        for address in range(int(start), int(end)):
            ip = first_three.group(1) + str(address)
            ping = get_ping_ms_response(ip, detected_os)
            name = nslooky(ip, detected_os)
            mac = get_mac(ip, detected_os)
            if csv_out:
                wr.writerow([ip, ping, name, mac])
            print_it(ip, ping, name, mac)

    if csv_out:
        myfile.close()


def main(ip=None, start=1, end=255, run_now=False, csv_out=False):
    """
    Main program body.

    :param ip: string
    :param start: int
    :param end: int
    :param run_now: boolean
    :param csv_out: boolean
    :return: None
    """
    answer = int()
    ip_range = sorted([int(start), int(end)])  # Ensure range sorted from low to high
    if csv_out == True:
        title_check(folder_name, csv_file_name)
    if run_now == True:
        get_results(ip, folder_name, csv_file_name,
                    end=ip_range[1], start=ip_range[0],
                    csv_out=csv_out, one_entry=False)
        print("")
        sys.exit()

    while answer != 3:
        print("\nQuery based on IP: {0}\n"
              "1) Continue with detected IP (entries for x.x.x.{1}-{2})\n"
              "2) Enter another IP (creates one entry)\n"
              "3) Exit".format(ip, ip_range[0], int(ip_range[1])))
        try:
            answer = int(input("Selection? "))
            if answer == 1:
                get_results(ip, folder_name, csv_file_name,
                            end=ip_range[1], start=ip_range[0],
                            csv_out=csv_out, one_entry=False)
            elif answer == 2:  # Manually enter IP
                choiceIP = input("\nInput IP: ")
                if ip_check(choiceIP):
                    get_results(choiceIP, folder_name, csv_file_name,
                                start=ip_range[0], end=ip_range[1],
                                csv_out=csv_out, one_entry=True)
                else:
                    print("\nInvalid IP.")
            elif answer == 3:
                sys.exit()
        except ValueError:
            print("\n")
            print("Invalid entry. Try again.")


if __name__ == "__main__":
    # metavar hack from:
    # http://stackoverflow.com/questions/16968188/
    # how-do-i-avoid-the-capital-placeholders-in-pythons-argparse-module
    parser = argparse.ArgumentParser(description="HostMAC")
    parser.add_argument("-c", "--csv", help="log output to csv", action="store_true",
                        required=False)
    parser.add_argument("-i", "--ip", default=detect_ip(),
                        help="specify ip, default: current ip", required=False)
    parser.add_argument("-r", "--run", help="run immediately (no menu); "
                        "optionally use --start and/or --end", action="store_true",
                        required=False)
    parser.add_argument("-s", "--start", default=1, type=int, choices=range(1, 254),
                        metavar="\b", help="start of range", required=False)
    parser.add_argument("-e", "--end", default=255, type=int, choices=range(2, 255),
                        metavar="\b", help="end of range", required=False)
    args = parser.parse_args()
    try:
        main(
            ip=args.ip, 
             start=args.start, 
             end=args.end,
             run_now=args.run, 
             csv_out=args.csv
        )
    except KeyboardInterrupt:
        print("\nCanceled by user.. Exiting.")
