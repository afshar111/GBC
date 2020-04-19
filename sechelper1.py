#!/usr/bin/python3
import pyshark
import nmap
import subprocess

print("Welcome, this is a simple PenTest automation tool")
print("<----------------------------------------------------->")

def passcrack():
    resp1 = input("""\nPlease enter the file that includs hashs \n""")
    print("You have enterd : ", resp1)
#    resp2 = input("""\nPlease enter the hash format \n""")
#    print("You have enterd : ", resp2)
    subprocess.call(["john", "--format=raw-md5", 
    "--wordlist=/usr/share/wordlists/rockyou.txt" , resp1])
    return
def vulscan() :
    ip_addr = input("Please enter the IP address you want to vul scan: ")
    print("The IP you entered is: ", ip_addr)	 
    subprocess.call(["nmap","-Pn", ip_addr])
    return
    
def runsrv() :
    ip_addr = input("Please enter the IP address you want to scan its services: ")
    print("The IP you entered is: ", ip_addr)	 
    subprocess.call(["nmap","-sV", ip_addr])
    return
    
def osint() :
    url = input("Please enter the URL to gathering info about: ")
    print("The URL you entered is: ", url)	 
    subprocess.call(["theHarvester", "-d" , url , "-b", "google"])   
    return  
    
def scan() :
    scanner = nmap.PortScanner()
    ip_addr = input("Please enter the IP address you want to scan: ")
    print("The IP you entered is: ", ip_addr)
    type(ip_addr)

    resp = input("""\nPlease enter the type of scan you want to run
                1)Ack Scan
                2)Xmas Scan
		3)FIN Scan
                4)SYN Scan \n""")
    print("You have selected option: ", resp)

    if resp == '1':
        print("Nmap Version: ", scanner.nmap_version())
        scanner.scan(ip_addr, '1-1024', '-v -sA')
        print(scanner.scaninfo())
        print("Ip Status: ", scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
#        print("Open Ports: ", scanner.scan())
        subprocess.call(["nmap","-sA", ip_addr])
    elif resp == '2':
        print("Nmap Version: ", scanner.nmap_version())
        scanner.scan(ip_addr, '1-1024', '-v -sX')
        print(scanner.scaninfo())
        print("Ip Status: ", scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
        print("Open Ports: ", scanner[ip_addr]['udp'].keys())
    elif resp == '3':
        print("Nmap Version: ", scanner.nmap_version())
        scanner.scan(ip_addr, '1-1024', '-v -sF')
        print(scanner.scaninfo())
        print("Ip Status: ", scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
        print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
    elif resp == '4':
        print("Nmap Version: ", scanner.nmap_version())
        scanner.scan(ip_addr, '1-1024', '-v -sS')
        print(scanner.scaninfo())
        print("Ip Status: ", scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
        print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
    elif resp >= '5':
        print("Please enter a valid option")
    return 

def snif() :
    
    T = input("Please enter the duration that to snif in Second: ")
    print("The Time you entered is: ", T," Second")
    Ofile = input("Please enter the the file name to save result: ")	 
    subprocess.call(["tcpdump", "-G" , T , "-w", "Ofile"])   
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
Mainresp = input("""\nPlease enter your option number:
                1. IP/Port Scanning 
                2. Network sniffer
                3. Cracking password
                4. Collect Email/banner/phones/URLs from URL. 
                5. vulnerability scanning
                6. display running services \n""")
print("You have selected option: ", Mainresp)
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
