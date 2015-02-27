#!/usr/bin/python

import Queue
import threading
import getopt
import sys
import urllib2
import hashlib
import socket
import time
import os
import re
import netaddr

#Max Scanning Thread Count
max_threads = 40

output= []

def test_ip(ip_address, identifier):
        #Identifier is not used
        IP = ip_address.strip()
        try:
                socket.inet_aton(IP)
        except:
                print "%s,invalid IP" % IP
                return

        try:
                response = urllib2.urlopen("https://%s/xmldata?item=All" % IP,timeout=6)
                response_body = response.read()
                firmware_version = ""
                ilo_version = ""
                if "FWRI" in response_body:
                        firmware_version = re.search("<FWRI>(.*?)<",response_body).group(1)
                if "PN" in response_body:
                        ilo_version = re.search("<PN>.*\((.*?)\)<",response_body).group(1)
                #check_vulnerable(IP,ilo_version,firmware_version)
                #print "%s,%s,%s" % (IP, ilo_version,firmware_version)
                #output.append("%s,%s,%s" % (IP, ilo_version,firmware_version))

        except:
                print "%s,Unresponsive or Not HP iLO" % IP
                return

        check_vulnerable(IP,ilo_version,firmware_version)


def usage():
        #Print usage
        print "ilo_version_scan.py"
        print "iLO and Firmware Version Scanner"
        print "Author: Scott Pack, InfoSec, Adobe DMa"
        print "Options:"
        print "-i <inputfile>"
        print "inputfile must consist of line-delimited IPv4 Addresses or CIDR ranges."

def print_header():
        print "ip,ilo_version,firmware_version,heartbleed_vulnerable,bridges_interfaces,ipmi_zero"

def check_vulnerable(IP,ilo,fw):
        ilo_v = ""
        fw_v = ""
        fw_sub_v = ""

        if ilo == "iLO":
                ilo_v = "1"
        else:
                ilo_v = re.search("iLO (.*)",ilo).group(1)
        fw_v = re.search("^(.*?)\.",fw).group(1)
        fw_sub_v = re.search("^.*?\.(.*)$",fw).group(1)

        ilo_v = int(ilo_v)
        fw_v = int(fw_v)
        fw_sub_v = int(fw_sub_v)


        heartbleed = False
        bridge_interfaces = False
        ipmi_zero = False

        #Heartbleed DOS, http://h20564.www2.hp.com/hpsc/doc/public/display?docId=emr_na-c04249852
        #Versions
        if (ilo_v==2 and fw_v==1) or (ilo_v==2 and fw_v==2 and fw_sub_v<25) or (ilo_v==1 and fw_v==1 and fw_sub_v<96):
                heartbleed = True
        if fw_v==1 and fw_sub_v==30:
                bridge_interfaces = True
        if (ilo_v==3 and fw_v<2 and fw_sub_v<61) or (ilo_v==4 and fw_v<2 and fw_sub_v<30):
                ipmi_zero = True

        output.append("%s,%s,%s,%s,%s,%s" % (IP, ilo, fw, heartbleed, bridge_interfaces,ipmi_zero))

def main():
        #read IP Addresses to Scan
        input_filename = ""
        attack_ports = [443]
        try:
                opts, args = getopt.getopt(sys.argv[1:],"i:p:o:")
        except getopt.GetoptError as err:
                print str(err)
                usage()
                sys.exit()

        #Get our opts in place.
        for o, a in opts:
                if o == "-h":
                        usage()
                        return
                elif o == "-i":
                        input_filename = a

        if input_filename == "":
                usage()
                return

        input_file = open(input_filename,"r")
        ips = []

        for line in input_file:
                line = line.strip()
                try:
                        socket.inet_aton(line)
                        ips.append(line)
                except:
                        pass
                if "/" in line:
                        try:
                                for ip in netaddr.IPNetwork(line):
                                        ips.append(str(ip))
                        except:
                                pass

        count = len(ips)
        dur = 3 + 5 + (count/max_threads)*6

        print "This scan for %s IPs will likely take %s seconds" % (count, dur)
        print "Starting scan now..."

        for IP in ips:
                t=threading.Thread(target=test_ip,args=(IP,""))
                t.daemon = True
                t.start()
                while (threading.activeCount()) >= max_threads:
                        #print "Hit max thread count (%s/%s), waiting 5 seconds\n" % (str(threading.activeCount()),max_threads)
                        time.sleep(3)

#       print("Finished list, waiting for threads to close.")

        while (threading.activeCount() > 2):
#               print "Waiting for %s threads to close" % threading.activeCount()
                time.sleep(5)
        time.sleep(5)


        print_header()
        for line in output:
                print line

main()
