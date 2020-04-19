#!/usr/bin/python3
import pyshark
import nmap
import subprocess
from prettytable import PrettyTable

print("Welcome, this is a simple PenTest automation tool")
print("<----------------------------------------------------->")
print("<----------------------------------------------------->")

def scan() :
    scanner = nmap.PortScanner()
    ip_addr = input("Please enter the IP address you want to scan: ")
    print("The IP you entered is: ", ip_addr)
    type(ip_addr)
    
    x = PrettyTable()

    x.field_names = ["Option", "Type of Scan"]

    x.add_row(["1", "SYN Sacn"])
    x.add_row(["2", "Xmas Scan"])
    x.add_row(["3", "FIN Scan"])
    x.add_row(["4", "Ack Scan"])
    

    print(x)    	   

    resp = input("""\nPlease enter the type of scan you want to run\n""")
    print("You have selected option: ", resp)
    print("<----------------------------------------------------->")
    print("<-------------------Please Wait----------------------->")
    if resp == '1':
        print("Nmap Version: ", scanner.nmap_version())
        scanner.scan(ip_addr, '1-1024', '-v -sS')
        print(scanner.scaninfo())
        print("Ip Status: ", scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
        print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
        
    elif resp == '2':
        print("Nmap Version: ", scanner.nmap_version())
        scanner.scan(ip_addr, '1-1024', '-v -sX')
        print(scanner.scaninfo())
        print("Ip Status: ", scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
#        print("Open Ports: ", scanner[ip_addr]['udp'].keys())
        subprocess.call(["nmap","-sX", ip_addr])
    elif resp == '3':
        print("Nmap Version: ", scanner.nmap_version())
        scanner.scan(ip_addr, '1-1024', '-v -sF')
        print(scanner.scaninfo())
        print("Ip Status: ", scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
#        print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
        subprocess.call(["nmap","-sF", ip_addr])
    elif resp == '4':
        print("Nmap Version: ", scanner.nmap_version())
        scanner.scan(ip_addr, '1-1024', '-v -sA')
        print(scanner.scaninfo())
        print("Ip Status: ", scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
#        print("Open Ports: ", scanner.scan())
        subprocess.call(["nmap","-sA", ip_addr])
        
    elif resp >= '5':
        print("Please enter a valid option")
    print("<----------------------------------------------------->")    
    return 
def passcrack():
    resp1 = input("""\nPlease enter the file that includs hashs \n""")
    print("You have enterd : ", resp1)
#    resp2 = input("""\nPlease enter the hash format \n""")
#    print("You have enterd : ", resp2)
    print("<----------------------------------------------------->")
    print("<-------------------Please Wait----------------------->")
    subprocess.call(["john", "--format=raw-md5", 
    "--wordlist=/usr/share/wordlists/rockyou.txt" , resp1])
    print("<----------------------------------------------------->")
    return
def vulscan() :
    ip_addr = input("Please enter the IP address you want to vul scan: ")
    print("The IP you entered is: ", ip_addr)	
    print("<----------------------------------------------------->")
    print("<-------------------Please Wait----------------------->") 
    subprocess.call(["nmap","-Pn", ip_addr])
    print("<----------------------------------------------------->")
    return
    
def runsrv() :
    ip_addr = input("Please enter the IP address you want to scan its services: ")
    print("The IP you entered is: ", ip_addr)	
    print("<----------------------------------------------------->")
    print("<-------------------Please Wait----------------------->") 
    subprocess.call(["nmap","-sV", ip_addr])
    print("<----------------------------------------------------->")
    return
    
def osint() :
    url = input("Please enter the URL to gathering info about: ")
    print("The URL you entered is: ", url)
    print("<----------------------------------------------------->")
    print("<-------------------Please Wait----------------------->")	 
    subprocess.call(["theHarvester", "-d" , url , "-b", "all"]) 
    print("<----------------------------------------------------->")  
    return  
    


def snif() :
    
    T = input("Please enter the duration that to snif in Second: ")
    print("The Time you entered is: ", T," Second")
    Ofile = input("Please enter the the file name to save result: ")
    print("<----------------------------------------------------->")
    print("<-------------------Please Wait----------------------->")	 
    subprocess.call(["tcpdump", "-G" , T , "-w", Ofile]) 
    print("<----------------------------------------------------->")  
#    capture = pyshark.LiveCapture(interface='eth0')
#    capture.sniff(timeout=5)
#    out_string=""
#    i=1
#    for packet in capture.sniff_continuously(packet_count=5):
#    	out_file = open("Eavesdrop_Data.txt", "w")
#    	out_string += "Packet #         " + str(i)
#    	out_string += "\n"
#    	out_string += str(packet)
#    	out_string += "\n"
#    	out_file.write(out_string)
#    	i = i + 1
#    	print ('Just arrived:', packet) 
    return


    
x = PrettyTable()

x.field_names = ["Option", "Tools"]

x.add_row(["1", "IP/Port Scanning"])
x.add_row(["2", "Network sniffer"])
x.add_row(["3", "Cracking password"])
x.add_row(["4", "Collect Email/banner/phones/URLs from URL."])
x.add_row(["5", "Vulnerability scanning"])
x.add_row(["6", "Display running services"])


print(x)    	   
Mainresp = input("""\nPlease enter your option number:\n""")
print("You have selected option: ", Mainresp)
print("<----------------------------------------------------->")
if Mainresp == '1':
        scan()
elif Mainresp == '2':
        snif()
elif Mainresp == '3':
        passcrack()
elif Mainresp == '4':
        osint()        
elif Mainresp == '5':
        vulscan()        
elif Mainresp == '6':
        runsrv()  
elif Mainresp >= '6':
        print("Please enter a valid option")        
        
print("<----------------------------------------------------->")
print("<----------------Testing Finished--------------------->")  
     


   
